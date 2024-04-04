package lib

import (
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/pkg/errors"

	"github.com/holiman/uint256"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/golang/glog"
	"github.com/shibukawa/configdir"
)

const (
	// ConfigDirVendorName is the enclosing folder for user data.
	// It's required to created a ConfigDir.
	ConfigDirVendorName = "deso"
	// ConfigDirAppName is the folder where we keep user data.
	ConfigDirAppName = "deso"
	// UseridLengthBytes is the number of bytes of entropy to use for
	// a userid.
	UseridLengthBytes = 32

	// These constants are used by the DNS seed code to pick a random last
	// seen time.
	SecondsIn3Days int32 = 24 * 60 * 60 * 3
	SecondsIn4Days int32 = 24 * 60 * 60 * 4

	// MessagesToFetchPerCall is used to limit the number of messages to fetch
	// when getting a user's inbox.
	MessagesToFetchPerInboxCall = 10000
)

type NodeMessage uint32

const (
	NodeRestart NodeMessage = iota
	NodeErase
)

// Time constants
const (
	NanoSecondsPerSecond = int64(1000000000)
)

func SecondsToNanoSeconds(secs int64) int64 {
	return secs * NanoSecondsPerSecond
}

func NanoSecondsToSeconds(nanos int64) int64 {
	return nanos / NanoSecondsPerSecond
}

func NanoSecondsToUint64MicroSeconds(nanos int64) uint64 {
	if nanos < 0 {
		return 0
	}
	return uint64(nanos / 1000)
}

func NanoSecondsToTime(nanos int64) time.Time {
	return time.Unix(0, nanos)
}

// Snapshot constants
const (
	// GetSnapshotTimeout is used in Peer when we fetch a snapshot chunk, and we need to retry.
	GetSnapshotTimeout = 100 * time.Millisecond

	// SnapshotBlockHeightPeriod is the constant height offset between individual snapshot epochs.
	SnapshotBlockHeightPeriod uint64 = 1000

	// SnapshotBatchSize is the size in bytes of the snapshot batches sent to peers
	SnapshotBatchSize uint32 = 100 << 20 // 100MB

	// DatabaseCacheSize is used to save read operations when fetching records from the main Db.
	DatabaseCacheSize uint = 1000000 // 1M

	// HashToCurveCache is used to save computation on hashing to curve.
	HashToCurveCache uint = 10000 // 10K

	// MetadataRetryCount is used to retry updating data in badger just in case.
	MetadataRetryCount int = 5

	// EnableTimer
	EnableTimer  = true
	DisableTimer = false
)

type NetworkType uint64

const (
	// The different network types. For now we have a mainnet and a testnet.
	// Also create an UNSET value to catch errors.
	NetworkType_UNSET   NetworkType = 0
	NetworkType_MAINNET NetworkType = 1
	NetworkType_TESTNET NetworkType = 2
)

type MsgDeSoHeaderVersion = uint32

const (
	// This is the header version that the blockchain started with.
	HeaderVersion0 = MsgDeSoHeaderVersion(0)
	// This version made several changes to the previous header encoding format:
	// - The Nonce field was expanded to 64 bits
	// - Another ExtraNonce field was added to provide *another* 64 bits of entropy,
	//   for a total of 128 bits of entropy in the header that miners can twiddle.
	// - The header height was expanded to 64 bits
	// - The TstampSecs were expanded to 64 bits
	// - All fields were moved from encoding in little-endian to big-endian
	//
	// The benefit of this change is that miners can hash over a wider space without
	// needing to twiddle ExtraData ever.
	//
	// At the time of this writing, the intent is to deploy it in a backwards-compatible
	// fashion, with the eventual goal of phasing out blocks with the previous version.
	HeaderVersion1 = MsgDeSoHeaderVersion(1)
	// This version introduces the transition from Proof of Work to Proof of Stake blocks.
	// It includes several changes to the header format:
	// - Nonce field is deprecated
	// - ExtraNonce field is deprecated
	// - ProposerPublicKey field is added
	// - ProposerVotingPublicKey field is added
	// - ProposedInView field is added
	// - ValidatorsVoteQC field is added
	// - ValidatorsTimeoutAggregateQC field is added
	// - ProposerVotePartialSignature field is added
	//
	// This format change is a breaking change that is not backwards-compatible with
	// versions 0 and 1.
	HeaderVersion2 = MsgDeSoHeaderVersion(2)
	// TODO: rename this "CurrentHeaderVersion" to "LatestProofOfWorkHeaderVersion". Note,
	// doing so will be a breaking change for 3rd party applications that import core and
	// use this constant.
	//
	// This CurrentHeaderVersion is an implicit version type that represents the latest
	// backwards compatible Proof of Work header format. This value is now locked to
	// HeaderVersion1 since versions 2 and onwards will be used for Proof of Stake formats.
	CurrentHeaderVersion = HeaderVersion1
)

// Versioning for the MsgValidatorVote message type. This type alias is equivalent
// to a uint8, and supports the same byte encoders/decoders.
type MsgValidatorVoteVersion = byte

const (
	MsgValidatorVoteVersion0 MsgValidatorVoteVersion = 0
)

// Versioning for the MsgValidatorTimeout message type. This type alias is equivalent
// to a uint8, and supports the same byte encoders/decoders.
type MsgValidatorTimeoutVersion = byte

const (
	MsgValidatorTimeoutVersion0 MsgValidatorTimeoutVersion = 0
)

var (
	MaxUint256, _ = uint256.FromHex("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	// These values are used by the DAOCoinLimitOrder logic in order to convert
	// fixed-point numbers to and from their exponentiated representation. For
	// more info on how this works, see the comment on DAOCoinLimitOrderEntry.
	//
	// This value is a uint256 form of 1e38, or 10^38. We mainly use it to represent a
	// "fixed-point" exchange rate when processing limit orders. See the comment on
	// DAOCoinLimitOrderEntry for more info.
	OneE38, _ = uint256.FromHex("0x4b3b4ca85a86c47a098a224000000000") // 1e38
	// This is the number of base units within a single "coin". It is mainly used to
	// convert from base units, which is what we deal with in core, to a human-readable
	// value in the UI. It is equal to 1e18.
	BaseUnitsPerCoin, _ = uint256.FromHex("0xde0b6b3a7640000") // 1e18
)

func (nt NetworkType) String() string {
	switch nt {
	case NetworkType_UNSET:
		return "UNSET"
	case NetworkType_MAINNET:
		return "MAINNET"
	case NetworkType_TESTNET:
		return "TESTNET"
	default:
		return fmt.Sprintf("UNRECOGNIZED(%d) - make sure String() is up to date", nt)
	}
}

const (
	MaxUsernameLengthBytes = 25
)

var (
	UsernameRegex = regexp.MustCompile("^[a-zA-Z0-9_]+$")
	// Profile pics are Base64 encoded plus ": ; ," used in the mime type spec.
	ProfilePicRegex = regexp.MustCompile("^[a-zA-Z0-9+/:;,]+$")

	TikTokShortURLRegex = regexp.MustCompile("^.*(vm\\.tiktok\\.com/)([A-Za-z0-9]{6,12}).*")
	TikTokFullURLRegex  = regexp.MustCompile("^.*((tiktok\\.com/)(v/)|(@[A-Za-z0-9_-]{2,24}/video/)|(embed/v2/))(\\d{0,30}).*")
)

type ForkHeights struct {
	// Global Block Heights:
	// The block height at which various forks occurred including an
	// explanation as to why they're necessary.

	// A dummy height set to zero by default.
	DefaultHeight uint64

	// The most deflationary event in DeSo history has yet to come...
	DeflationBombBlockHeight uint64

	// SalomonFixBlockHeight defines a block height where the protocol implements
	// two changes:
	// 	(1) The protocol now prints founder reward for all buy transactions instead
	//		of just when creators reach a new all time high.
	//		This was decided in order to provide lasting incentive for creators
	//		to utilize the protocol.
	//	(2) A fix was created to deal with a bug accidentally triggered by @salomon.
	//		After a series of buys and sells @salomon was left with a single creator coin
	//		nano in circulation and a single DeSo nano locked. This caused a detach
	//		between @salomon's bonding curve and others on the protocol. As more buys and sells
	//		continued, @salomon's bonding curve continued to detach further and further from its peers.
	// 		At its core, @salomon had too few creator coins in circulation. This fix introduces
	//		this missing supply back into circulation as well as prevented detached Bancor bonding
	//		curves from coming into existence.
	//		^ It was later decided to leave Salomon's coin circulation alone. A fix was introduced
	//		to prevent similar cases from occurring again, but @salomon is left alone.
	SalomonFixBlockHeight uint32

	// DeSoFounderRewardBlockHeight defines a block height where the protocol switches from
	// paying the founder reward in the founder's own creator coin to paying in DeSo instead.
	DeSoFounderRewardBlockHeight uint32

	// BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight defines a block height after which the protocol will create
	// a new BalanceEntry when a user purchases a Creator Coin and their current BalanceEntry is deleted.
	// The situation in which a BalanceEntry reaches a deleted state occurs when a user transfers all their holdings
	// of a certain creator to another public key and subsequently purchases that same creator within the same block.
	// This resolves a bug in which users would purchase creator coins after transferring all holdings within the same
	// block and then the creator coins would be added to a deleted balance.  When the Balance Entries are flushed to
	// the database, the user would lose the creator coins they purchased.
	BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight uint32

	// ParamUpdaterProfileUpdateFixBlockHeight defines a block height after which the protocol uses the update profile
	// txMeta's ProfilePublicKey when the Param Updater is creating a profile for ProfilePublicKey.
	ParamUpdaterProfileUpdateFixBlockHeight uint32

	// UpdateProfileFixBlockHeight defines the height at which a patch was added to prevent user from
	// updating the profile entry for arbitrary public keys that do not have existing profile entries.
	UpdateProfileFixBlockHeight uint32

	// BrokenNFTBidsFixBlockHeight defines the height at which the deso balance index takes effect
	// for accepting NFT bids.  This is used to fix a fork that was created by nodes running with a corrupted
	// deso balance index, allowing bids to be submitted that were greater than the user's deso balance.
	BrokenNFTBidsFixBlockHeight uint32

	// DeSoDiamondsBlockHeight defines the height at which diamonds will be given in DESO
	// rather than in creator coin.
	// Triggers: 3pm PT on 8/16/2021
	DeSoDiamondsBlockHeight uint32

	// NFTTransfersBlockHeight defines the height at which NFT transfer txns, accept NFT
	// transfer txns, NFT burn txns, and AuthorizeDerivedKey txns will be accepted.
	// Triggers: 12PM PT on 9/15/2021
	NFTTransferOrBurnAndDerivedKeysBlockHeight uint32

	// DeSoV3MessagesBlockHeight defines the height at which messaging key and messsage party
	// entries will be accepted by consensus.
	DeSoV3MessagesBlockHeight uint32

	// BuyNowAndNFTSplitsBlockHeight defines the height at which NFTs can be sold at a fixed price instead of an
	// auction style and allows splitting of NFT royalties to user's other than the post's creator.
	BuyNowAndNFTSplitsBlockHeight uint32

	// DAOCoinBlockHeight defines the height at which DAO Coin and DAO Coin Transfer
	// transactions will be accepted.
	DAOCoinBlockHeight uint32

	ExtraDataOnEntriesBlockHeight uint32

	// DerivedKeySetSpendingLimitsBlockHeight defines the height at which derived key transactions will have their
	// transaction spending limits in the extra data field parsed.
	DerivedKeySetSpendingLimitsBlockHeight uint32

	// DerivedKeyTrackSpendingLimitsBlockHeight defines the height at which derived key's transaction spending limits
	// will come in effect - accounting of DESO spent and transaction counts will begin at this height. These heights
	// are separated to allow developers time to generate new derived keys for their users. NOTE: this must always
	// be greater than or equal to DerivedKeySetSpendingLimitsBlockHeight.
	DerivedKeyTrackSpendingLimitsBlockHeight uint32

	// DAOCoinLimitOrderBlockHeight defines the height at which DAO Coin Limit Order transactions will be accepted.
	DAOCoinLimitOrderBlockHeight uint32

	// DerivedKeyEthSignatureCompatibilityBlockHeight allows authenticating derived keys that were signed with the Ethereum
	// personal_sign signature standard. This in particular allows the usage of MetaMask for issuing derived keys.
	DerivedKeyEthSignatureCompatibilityBlockHeight uint32

	// OrderBookDBFetchOptimizationBlockHeight implements an optimization around fetching orders from the db.
	OrderBookDBFetchOptimizationBlockHeight uint32

	// ParamUpdaterRefactorBlockHeight indicates a point at which we refactored
	// ParamUpdater to use a blockHeight-gated function rather than a constant.
	ParamUpdaterRefactorBlockHeight uint32

	// DeSoUnlimitedDerivedKeysBlockHeight defines the height at which
	// we introduce derived keys without a spending limit.
	DeSoUnlimitedDerivedKeysBlockHeight uint32

	// AssociationsAndAccessGroupsBlockHeight defines the height at which we introduced:
	//   - Access Groups
	//   - User and Post Associations
	//   - Editable NFT posts
	//   - Frozen posts
	AssociationsAndAccessGroupsBlockHeight uint32

	// AssociationsDerivedKeySpendingLimitBlockHeight defines the height at which we
	// introduced a few improvements for associations' derived key spending limits.
	AssociationsDerivedKeySpendingLimitBlockHeight uint32

	// BalanceModelBlockHeight defines the height at which we convert from a UTXO model
	// to an account balance model for accounting.
	BalanceModelBlockHeight uint32

	// BlockRewardPatchBlockHeight defines the height at which the block reward excludes
	// transaction fees from the public key receiving the block reward. This prevents
	// the recipient of the block reward from paying nothing for their transactions
	// that are in the block.
	BlockRewardPatchBlockHeight uint32

	// ProofOfStake1StateSetupBlockHeight defines the height at which we introduced all
	// changes to set up the prerequisite state for cutting over to PoS consensus. These
	// changes include, for example, introducing the new PoS txn types, consensus params,
	// leader schedule generation, and snapshotting.
	//
	// The ProofOfStake1StateSetupBlockHeight needs to be set before the
	// ProofOfStake2ConsensusCutoverBlockHeight so that we allow time for validators to
	// register, stake to be assigned, and the validator set, consensus params, and
	// leader schedule snapshots to be generated in advance.
	ProofOfStake1StateSetupBlockHeight uint32

	// LockupsBlockHeight defines the height at which we begin accepting lockup
	// related transactions. These can include things like CoinLockup, UpdateCoinLockupParams,
	// CoinLockupTransfer, and CoinUnlock.
	//
	// We specify this separately to enable independent testing when compared with other features.
	LockupsBlockHeight uint32

	// ProofOfStake2ConsensusCutoverBlockHeight defines the height at which we cut over
	// from PoW consensus to PoS consensus.
	ProofOfStake2ConsensusCutoverBlockHeight uint32

	// Be sure to update EncoderMigrationHeights as well via
	// GetEncoderMigrationHeights if you're modifying schema.
}

// MigrationName is used to store migration heights for DeSoEncoder types. To properly migrate a DeSoEncoder,
// you should:
//  0. Typically, encoder migrations should align with hard fork heights. So the first
//     step is to define a new value in ForkHeights, and set the value accordingly for
//     mainnet, testnet, and regtest param structs. Add a name for your migration so that
//     it can be accessed robustly.
//  1. Define a new block height in the EncoderMigrationHeights struct. This should map
//     1:1 with the fork height defined prior.
//  2. Add conditional statements to the RawEncode / RawDecodeWithoutMetadata methods that
//     trigger at the defined height.
//  3. Add a condition to GetVersionByte to return version associated with the migration height.
//
// So for example, let's say you want to add a migration for UtxoEntry at height 1200.
//
//  0. Add a field to ForkHeight that marks the point at which this entry will come
//     into play:
//     - Add the following to the ForkHeight struct:
//     UtxoEntryTestHeight uint64
//     - Add the following to the individual param structs (MainnetForkHeights, TestnetForkHeights,
//     and RegtestForkHeights):
//     UtxoEntryTestHeight: 1200 (may differ for mainnet vs testnet & regtest)
//     - Add the migration name below DefaultMigration
//     UtxoEntryTestHeight MigrationName = "UtxoEntryTestHeight"
//
//  1. Add a field to the EncoderMigrationHeights that looks like this:
//     UtxoEntryTestHeight MigrationHeight
//
//  2. Modify func (utxoEntry *UtxoEntry) RawEncode/RawDecodeWithoutMetadata. E.g. add the following condition at the
//     end of RawEncodeWithoutMetadata (note the usage of the MigrationName UtxoEntryTestHeight):
//     if MigrationTriggered(blockHeight, UtxoEntryTestHeight) {
//     data = append(data, byte(127))
//     }
//     And this at the end of RawDecodeWithoutMetadata:
//     if MigrationTriggered(blockHeight, UtxoEntryTestHeight) {
//     _, err = rr.ReadByte()
//     if err != nil {
//     return errors.Wrapf(err, "UtxoEntry.Decode: Problem reading random byte.")
//     }
//     }
//     MAKE SURE TO WRITE CORRECT CONDITIONS FOR THE HEIGHTS IN BOTH ENCODE AND DECODE!
//
//  3. Modify func (utxo *UtxoEntry) GetVersionByte to return the correct encoding version depending on the height. Use the
//     function GetMigrationVersion to chain encoder migrations (Note the variadic parameter of GetMigrationVersion and
//     the usage of the MigrationName UtxoEntryTestHeight)
//
//     return GetMigrationVersion(blockHeight, UtxoEntryTestHeight)
//
// That's it!
type MigrationName string
type MigrationHeight struct {
	Height  uint64
	Version byte
	Name    MigrationName
}

const (
	DefaultMigration                     MigrationName = "DefaultMigration"
	UnlimitedDerivedKeysMigration        MigrationName = "UnlimitedDerivedKeysMigration"
	AssociationsAndAccessGroupsMigration MigrationName = "AssociationsAndAccessGroupsMigration"
	BalanceModelMigration                MigrationName = "BalanceModelMigration"
	ProofOfStake1StateSetupMigration     MigrationName = "ProofOfStake1StateSetupMigration"
)

type EncoderMigrationHeights struct {
	DefaultMigration MigrationHeight

	// DeSoUnlimitedDerivedKeys coincides with the DeSoUnlimitedDerivedKeysBlockHeight block
	DeSoUnlimitedDerivedKeys MigrationHeight

	// This coincides with the AssociationsAndAccessGroups block
	AssociationsAndAccessGroups MigrationHeight

	// This coincides with the BalanceModel block
	BalanceModel MigrationHeight

	// This coincides with the ProofOfStake1StateSetupBlockHeight
	ProofOfStake1StateSetupMigration MigrationHeight
}

func GetEncoderMigrationHeights(forkHeights *ForkHeights) *EncoderMigrationHeights {
	return &EncoderMigrationHeights{
		DefaultMigration: MigrationHeight{
			Version: 0,
			Height:  forkHeights.DefaultHeight,
			Name:    DefaultMigration,
		},
		DeSoUnlimitedDerivedKeys: MigrationHeight{
			Version: 1,
			Height:  uint64(forkHeights.DeSoUnlimitedDerivedKeysBlockHeight),
			Name:    UnlimitedDerivedKeysMigration,
		},
		AssociationsAndAccessGroups: MigrationHeight{
			Version: 2,
			Height:  uint64(forkHeights.AssociationsAndAccessGroupsBlockHeight),
			Name:    AssociationsAndAccessGroupsMigration,
		},
		BalanceModel: MigrationHeight{
			Version: 3,
			Height:  uint64(forkHeights.BalanceModelBlockHeight),
			Name:    BalanceModelMigration,
		},
		ProofOfStake1StateSetupMigration: MigrationHeight{
			Version: 4,
			Height:  uint64(forkHeights.ProofOfStake1StateSetupBlockHeight),
			Name:    ProofOfStake1StateSetupMigration,
		},
	}
}

func GetEncoderMigrationHeightsList(forkHeights *ForkHeights) (
	_migrationHeightsList []*MigrationHeight) {

	migrationHeights := GetEncoderMigrationHeights(forkHeights)

	// Read `version:"x"` tags from the EncoderMigrationHeights struct.
	var migrationHeightsList []*MigrationHeight
	elements := reflect.ValueOf(migrationHeights).Elem()
	structFields := elements.Type()
	for ii := 0; ii < structFields.NumField(); ii++ {
		elementField := elements.Field(ii)
		mig := elementField.Interface().(MigrationHeight)
		migCopy := mig
		migrationHeightsList = append(migrationHeightsList, &migCopy)
	}

	sort.Slice(migrationHeightsList, func(i int, j int) bool {
		return migrationHeightsList[i].Height < migrationHeightsList[j].Height
	})
	return migrationHeightsList
}

type ProtocolVersionType uint64

const (
	// ProtocolVersion0 is the first version of the DeSo protocol, running Proof of Work.
	ProtocolVersion0 ProtocolVersionType = 0
	// ProtocolVersion1 nodes run Proof of Work, and new node services such as rosetta, hypersync.
	// The version indicates that the node supports P2P features related to these new services.
	ProtocolVersion1 ProtocolVersionType = 1
	// ProtocolVersion2 is the latest version of the DeSo protocol, running Proof of Stake.
	ProtocolVersion2 ProtocolVersionType = 2
)

func NewProtocolVersionType(version uint64) ProtocolVersionType {
	return ProtocolVersionType(version)
}

func (pvt ProtocolVersionType) ToUint64() uint64 {
	return uint64(pvt)
}

func (pvt ProtocolVersionType) Before(version ProtocolVersionType) bool {
	return pvt.ToUint64() < version.ToUint64()
}

func (pvt ProtocolVersionType) After(version ProtocolVersionType) bool {
	return pvt.ToUint64() > version.ToUint64()
}

// DeSoParams defines the full list of possible parameters for the
// DeSo network.
type DeSoParams struct {
	// The network type (mainnet, testnet, etc).
	NetworkType NetworkType
	// Set to true when we're running in regtest mode. This is useful for testing.
	ExtraRegtestParamUpdaterKeys map[PkMapKey]bool
	// The current protocol version we're running.
	ProtocolVersion ProtocolVersionType
	// The minimum protocol version we'll allow a peer we connect to
	// to have.
	MinProtocolVersion uint64
	// Used as a "vanity plate" to identify different DeSo
	// clients. Mainly useful in analyzing the network at
	// a meta level, not in the protocol itself.
	UserAgent string
	// The list of DNS seed hosts to use during bootstrapping.
	DNSSeeds []string

	// A list of DNS seed prefixes and suffixes to use during bootstrapping.
	// These prefixes and suffixes will be scanned and all IPs found will be
	// incorporated into the address manager.
	DNSSeedGenerators [][]string

	// The network parameter for Bitcoin messages as defined by the btcd library.
	// Useful for certain function calls we make to this library.
	BitcoinBtcdParams *chaincfg.Params

	// Because we use the Bitcoin header chain only to process exchanges from
	// BTC to DeSo, we don't need to worry about Bitcoin blocks before a certain
	// point, which is specified by this node. This is basically used to make
	// header download more efficient but it's important to note that if for
	// some reason there becomes a different main chain that is stronger than
	// this one, then we will still switch to that one even with this parameter
	// set such as it is.
	BitcoinStartBlockNode *BlockNode

	// The base58Check-encoded Bitcoin address that users must send Bitcoin to in order
	// to purchase DeSo. Note that, unfortunately, simply using an all-zeros or
	// mostly-all-zeros address or public key doesn't work and, in fact, I found that
	// using almost any address other than this one also doesn't work.
	BitcoinBurnAddress string

	// This is a fee in basis points charged on BitcoinExchange transactions that gets
	// paid to the miners. Basically, if a user burned enough Satoshi to create 100 DeSo,
	// and if the BitcoinExchangeFeeBasisPoints was 1%, then 99 DeSo would be allocated to
	// the user's public key while 1 DeSo would be left as a transaction fee to the miner.
	BitcoinExchangeFeeBasisPoints uint64

	// The amount of time to wait for a Bitcoin txn to broadcast throughout the Bitcoin
	// network before checking for double-spends.
	BitcoinDoubleSpendWaitSeconds float64

	// ServerMessageChannelSize sets the minimum size of the server's incomingMessage channel, which handles peer messages.
	ServerMessageChannelSize uint32

	// This field allows us to set the amount purchased at genesis to a non-zero
	// value.
	DeSoNanosPurchasedAtGenesis uint64

	// Port used for network communications among full nodes.
	DefaultSocketPort uint16
	// Port used for the limited JSON API that supports light clients.
	DefaultJSONPort uint16

	// The amount of time we wait when connecting to a peer.
	DialTimeout time.Duration
	// The amount of time we wait to receive a version message from a peer.
	VersionNegotiationTimeout time.Duration
	// The amount of time we wait to receive a verack message from a peer.
	VerackNegotiationTimeout time.Duration

	// The amount of time it takes NetworkManager to refresh its routines.
	NetworkManagerRefreshDuration time.Duration

	// The maximum number of addresses to broadcast to peers.
	MaxAddressesToBroadcast uint32

	// The genesis block to use as the base of our chain.
	GenesisBlock *MsgDeSoBlock
	// The expected hash of the genesis block. Should align with what one
	// would get from actually hashing the provided genesis block.
	GenesisBlockHashHex string
	// How often we target a single block to be generated.
	TimeBetweenBlocks time.Duration
	// How many blocks between difficulty retargets.
	TimeBetweenDifficultyRetargets time.Duration
	// Block hashes, when interpreted as big-endian big integers, must be
	// values less than or equal to the difficulty
	// target. The difficulty target is expressed below as a big-endian
	// big integer and is adjusted every TargetTimePerBlock
	// order to keep blocks generating at consistent intervals.
	MinDifficultyTargetHex string
	// We will reject chains that have less than this amount of total work,
	// expressed as a hexadecimal big-endian bigint. Useful for preventing
	// disk-fill attacks, among other things.
	MinChainWorkHex string

	// This is used for determining whether we are still in initial block download
	// when the chain is running PoW.
	// If our tip is older than this, we continue with IBD.
	MaxTipAgePoW time.Duration

	// This is used for determining whether we are still in initial block download
	// when the chain is running PoS.
	// If our tip is older than this, we continue with initial block download.
	MaxTipAgePoS time.Duration

	// Do not allow the difficulty to change by more than a factor of this
	// variable during each adjustment period.
	MaxDifficultyRetargetFactor int64
	// Amount of time one must wait before a block reward can be spent.
	BlockRewardMaturity time.Duration
	// When shifting from v0 blocks to v1 blocks, we changed the hash function to
	// DeSoHash, which is technically easier. Thus we needed to apply an adjustment
	// factor in order to phase it in.
	V1DifficultyAdjustmentFactor int64

	// The maximum number of seconds in a future a block timestamp is allowed
	// to be before it is rejected.
	MaxTstampOffsetSeconds uint64

	// The maximum number of bytes that can be allocated to transactions in
	// a block.
	MaxBlockSizeBytesPoW uint64

	// It's useful to set the miner maximum block size to a little lower than the
	// maximum block size in certain cases. For example, on initial launch, setting
	// it significantly lower is a good way to avoid getting hit by spam blocks.
	MinerMaxBlockSizeBytes uint64

	// In order to make public keys more human-readable, we convert
	// them to base58. When we do that, we use a prefix that makes
	// the public keys to become more identifiable. For example, all
	// mainnet public keys start with "X" because we do this.
	Base58PrefixPublicKey  [3]byte
	Base58PrefixPrivateKey [3]byte

	// MaxFetchBlocks is the maximum number of blocks that can be fetched from
	// a peer at one time.
	MaxFetchBlocks uint32

	MiningIterationsPerCycle uint64

	// Snapshot
	// For PoW, we use a snapshot block height period of 1000 blocks. We record this value in the constants
	// as it'll be used during the PoW -> PoS transition. Notably, this value is used to allow PoS nodes
	// to hypersync from PoW nodes. In hypersync, knowing the snapshot block height period of the sync peer
	// is necessary to determine the block height of the snapshot we're going to receive.
	DefaultPoWSnapshotBlockHeightPeriod uint64

	// deso
	MaxUsernameLengthBytes        uint64
	MaxUserDescriptionLengthBytes uint64
	MaxProfilePicLengthBytes      uint64
	MaxProfilePicDimensions       uint64
	MaxPrivateMessageLengthBytes  uint64
	MaxNewMessageLengthBytes      uint64

	StakeFeeBasisPoints         uint64
	MaxPostBodyLengthBytes      uint64
	MaxPostSubLengthBytes       uint64
	MaxStakeMultipleBasisPoints uint64
	MaxCreatorBasisPoints       uint64
	MaxNFTRoyaltyBasisPoints    uint64

	// A list of transactions to apply when initializing the chain. Useful in
	// cases where we want to hard fork or reboot the chain with specific
	// transactions applied.
	SeedTxns []string

	// A list of balances to initialize the blockchain with. This is useful for
	// testing and useful in the event that the devs need to hard fork the chain.
	SeedBalances []*DeSoOutput

	// This is a small fee charged on creator coin transactions. It helps
	// prevent issues related to floating point calculations.
	CreatorCoinTradeFeeBasisPoints uint64
	// These two params define the "curve" that we use when someone buys/sells
	// creator coins. Effectively, this curve amounts to a polynomial of the form:
	// - currentCreatorCoinPrice ~= slope * currentCreatorCoinSupply^(1/reserveRatio-1)
	// Buys and sells effectively take the integral of the curve in opposite directions.
	//
	// To better understand where this curve comes from and how it works, check out
	// the following links. They are all well written so don't be intimidated/afraid to
	// dig in and read them:
	// - Primer on bonding curves: https://medium.com/@simondlr/tokens-2-0-curved-token-bonding-in-curation-markets-1764a2e0bee5
	// - The Uniswap v2 white paper: https://whitepaper.io/document/600/uniswap-whitepaper
	// - The Bancor white paper: https://whitepaper.io/document/52/bancor-whitepaper
	// - Article relating Bancor curves to polynomial curves: https://medium.com/@aventus/token-bonding-curves-547f3a04914
	// - Derivations of the Bancor supply increase/decrease formulas: https://blog.relevant.community/bonding-curves-in-depth-intuition-parametrization-d3905a681e0a
	// - Implementations of Bancor equations in Solidity with code: https://yos.io/2018/11/10/bonding-curves/
	// - Bancor is flawed blog post discussing Bancor edge cases: https://hackingdistributed.com/2017/06/19/bancor-is-flawed/
	// - A mathematica equation sheet with tests that walks through all the
	//   equations. You will need to copy this into a Mathematica notebook to
	//   run it: https://pastebin.com/raw/M4a1femY
	CreatorCoinSlope        *big.Float
	CreatorCoinReserveRatio *big.Float

	// CreatorCoinAutoSellThresholdNanos defines two things. The first is the minimum amount
	// of creator coins a user must purchase in order for a transaction to be valid. Secondly
	// it defines the point at which a sell operation will auto liquidate all remaining holdings.
	// For example if I hold 1000 nanos of creator coins and sell x nanos such that
	// 1000 - x < CreatorCoinAutoSellThresholdNanos, we auto liquidate the remaining holdings.
	// It does this to prevent issues with floating point rounding that can arise.
	// This value should be chosen such that the chain is resistant to "phantom nanos." Phantom nanos
	// are tiny amounts of CreatorCoinsInCirculation/DeSoLocked which can cause
	// the effective reserve ratio to deviate from the expected reserve ratio of the bancor curve.
	// A higher CreatorCoinAutoSellThresholdNanos makes it prohibitively expensive for someone to
	// attack the bancor curve to any meaningful measure.
	CreatorCoinAutoSellThresholdNanos uint64

	// DefaultStakeLockupEpochDuration is the default number of epochs
	// that a user must wait before unlocking their unstaked stake.
	DefaultStakeLockupEpochDuration uint64

	// DefaultValidatorJailEpochDuration is the default number of epochs
	// that a validator must wait after being jailed before submitting
	// an UnjailValidator txn.
	DefaultValidatorJailEpochDuration uint64

	// DefaultLeaderScheduleMaxNumValidators is the default maximum number of validators
	// that are included when generating a new Proof-of-Stake leader schedule.
	DefaultLeaderScheduleMaxNumValidators uint64

	// DefaultValidatorSetMaxNumValidators is the default maximum number of validators
	// that are included in the validator set for any given epoch.
	DefaultValidatorSetMaxNumValidators uint64

	// DefaultStakingRewardsMaxNumStakes is the default number of stake entries
	// that are included in the staking reward distribution in each epoch.
	DefaultStakingRewardsMaxNumStakes uint64

	// DefaultStakingRewardsAPYBasisPoints is the default scaled interest rate
	// that is applied to all stake entries in the staking reward distribution in each epoch.
	DefaultStakingRewardsAPYBasisPoints uint64

	// DefaultEpochDurationNumBlocks is the default number of blocks included in one epoch.
	DefaultEpochDurationNumBlocks uint64

	// DefaultJailInactiveValidatorGracePeriodEpochs is the default number of epochs
	// we allow a validator to be inactive for (neither voting nor proposing blocks)
	// before they are jailed.
	DefaultJailInactiveValidatorGracePeriodEpochs uint64

	// DefaultBlockTimestampDriftNanoSecs is the default number of nanoseconds
	// from the current timestamp that we will allow a PoS block to be submitted.
	DefaultBlockTimestampDriftNanoSecs int64

	// DefaultFeeBucketGrowthRateBasisPoints is the rate of growth of the fee bucket ranges. The multiplier is given
	// as basis points. For example a value of 1000 means that the fee bucket ranges will grow by 10% each time.
	DefaultFeeBucketGrowthRateBasisPoints uint64

	// DefaultMaximumVestedIntersectionsPerLockupTransaction is the default value for
	// GlobalParamsEntry.MaximumVestedIntersectionsPerLockupTransaction. See the comment
	// in GlobalParamsEntry for a detailed description of its usage.
	DefaultMaximumVestedIntersectionsPerLockupTransaction int

	// DefaultMempoolMaxSizeBytes is the default value for GlobalParamsEntry.MempoolMaxSizeBytes.
	// See the comment in GlobalParamsEntry for a description of its usage.
	DefaultMempoolMaxSizeBytes uint64

	// DefaultMempoolFeeEstimatorNumMempoolBlocks is the default value for
	// GlobalParamsEntry.MempoolFeeEstimatorNumMempoolBlocks. See the comment in GlobalParamsEntry
	// for a description of its usage.
	DefaultMempoolFeeEstimatorNumMempoolBlocks uint64

	// DefaultMempoolFeeEstimatorNumPastBlocks is the default value for
	// GlobalParamsEntry.MempoolFeeEstimatorNumPastBlocks. See the comment in GlobalParamsEntry
	// for a description of its usage.
	DefaultMempoolFeeEstimatorNumPastBlocks uint64

	// DefaultMaxBlockSizeBytesPoS is the default value for GlobalParamsEntry.MaxBlockSizeBytesPoS.
	// This is the initial value for the maximum block size in bytes that we allow for PoS blocks.
	DefaultMaxBlockSizeBytesPoS uint64

	// DefaultSoftMaxBlockSizeBytesPoS is the default value for GlobalParamsEntry.SoftMaxBlockSizeBytesPoS
	// This is the initial value for the ideal block size in bytes we aim for in block production and fee
	// estimation.
	DefaultSoftMaxBlockSizeBytesPoS uint64

	// DefaultMaxTxnSizeBytesPoS is the default value for GlobalParamsEntry.MaxTxnSizeBytesPoS.
	// This is the initial value for the maximum txn size in bytes that we allow for txns in PoS blocks.
	DefaultMaxTxnSizeBytesPoS uint64

	// DefaultBlockProductionIntervalMillisecondsPoS is the default value for GlobalParamsEntry.BlockProductionIntervalMillisecondsPoS.
	// This is the initial value for the interval between producing blocks.
	DefaultBlockProductionIntervalMillisecondsPoS uint64

	// DefaultTimeoutIntervalMillisecondsPoS is the default value for GlobalParamsEntry.TimeoutIntervalMillisecondsPoS.
	// This is the initial value for the interval between timing out a view.
	DefaultTimeoutIntervalMillisecondsPoS uint64

	// HandshakeTimeoutMicroSeconds is the timeout for the peer handshake certificate. The default value is 15 minutes.
	HandshakeTimeoutMicroSeconds uint64

	// DisableNetworkManagerRoutines is a testing flag that disables the network manager routines.
	DisableNetworkManagerRoutines bool

	ForkHeights ForkHeights

	EncoderMigrationHeights     *EncoderMigrationHeights
	EncoderMigrationHeightsList []*MigrationHeight
}

var RegtestForkHeights = ForkHeights{
	DefaultHeight:                0,
	DeflationBombBlockHeight:     0,
	SalomonFixBlockHeight:        uint32(0),
	DeSoFounderRewardBlockHeight: uint32(0),
	BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight: uint32(0),
	ParamUpdaterProfileUpdateFixBlockHeight:              uint32(0),
	UpdateProfileFixBlockHeight:                          uint32(0),
	BrokenNFTBidsFixBlockHeight:                          uint32(0),
	DeSoDiamondsBlockHeight:                              uint32(0),
	NFTTransferOrBurnAndDerivedKeysBlockHeight:           uint32(0),
	DeSoV3MessagesBlockHeight:                            uint32(0),
	BuyNowAndNFTSplitsBlockHeight:                        uint32(0),
	DAOCoinBlockHeight:                                   uint32(0),
	ExtraDataOnEntriesBlockHeight:                        uint32(0),
	DerivedKeySetSpendingLimitsBlockHeight:               uint32(0),
	DerivedKeyTrackSpendingLimitsBlockHeight:             uint32(0),
	DAOCoinLimitOrderBlockHeight:                         uint32(0),
	DerivedKeyEthSignatureCompatibilityBlockHeight:       uint32(0),
	OrderBookDBFetchOptimizationBlockHeight:              uint32(0),
	ParamUpdaterRefactorBlockHeight:                      uint32(0),
	DeSoUnlimitedDerivedKeysBlockHeight:                  uint32(0),
	AssociationsAndAccessGroupsBlockHeight:               uint32(0),
	AssociationsDerivedKeySpendingLimitBlockHeight:       uint32(0),
	// For convenience, we set the block height to 1 since the
	// genesis block was created using the utxo model.
	BalanceModelBlockHeight:            uint32(1),
	ProofOfStake1StateSetupBlockHeight: uint32(1),

	// For convenience, we set the PoS cutover block height to 300 so that
	// enough DESO is minted to allow for testing. The 300 number is tuned
	// to allow for 144 blocks/epoch * 2 epochs = 288 blocks to be mined
	// before the chain transitions to PoS. Two epoch transitions must take
	// place for the chain to set up the validator set to run PoS.
	ProofOfStake2ConsensusCutoverBlockHeight: uint32(300),

	LockupsBlockHeight: uint32(1),

	BlockRewardPatchBlockHeight: uint32(0),

	// Be sure to update EncoderMigrationHeights as well via
	// GetEncoderMigrationHeights if you're modifying schema.
}

// EnableRegtest allows for local development and testing with incredibly fast blocks with block rewards that
// can be spent as soon as they are mined. It also removes the default testnet seeds
func (params *DeSoParams) EnableRegtest() {
	if params.NetworkType != NetworkType_TESTNET {
		glog.Error("Regtest mode can only be enabled in testnet mode")
		return
	}

	// Add a key defined in n0_test to the ParamUpdater set when running in regtest mode.
	// Seed: verb find card ship another until version devote guilt strong lemon six
	params.ExtraRegtestParamUpdaterKeys = map[PkMapKey]bool{}
	params.ExtraRegtestParamUpdaterKeys[MakePkMapKey(MustBase58CheckDecode(
		"tBCKVERmG9nZpHTk2AVPqknWc1Mw9HHAnqrTpW1RnXpXMQ4PsQgnmV"))] = true

	// Clear the seeds
	params.DNSSeeds = []string{}

	// Set the protocol version
	params.ProtocolVersion = ProtocolVersion2

	// Mine blocks incredibly quickly
	params.TimeBetweenBlocks = 2 * time.Second
	params.TimeBetweenDifficultyRetargets = 6 * time.Second
	// Make sure we don't care about blockchain tip age.
	params.MaxTipAgePoW = 1000000 * time.Hour

	// Allow block rewards to be spent instantly
	params.BlockRewardMaturity = 0

	// Set the PoS default jail inactive validator grace period epochs to 3.
	params.DefaultJailInactiveValidatorGracePeriodEpochs = 3

	// In regtest, we start all the fork heights at zero. These can be adjusted
	// for testing purposes to ensure that a transition does not cause issues.
	params.ForkHeights = RegtestForkHeights
	params.EncoderMigrationHeights = GetEncoderMigrationHeights(&params.ForkHeights)
	params.EncoderMigrationHeightsList = GetEncoderMigrationHeightsList(&params.ForkHeights)
	params.DefaultStakingRewardsAPYBasisPoints = 100000 * 100 // 100000% for regtest
}

func (params *DeSoParams) IsPoWBlockHeight(blockHeight uint64) bool {
	return !params.IsPoSBlockHeight(blockHeight)
}

func (params *DeSoParams) IsPoSBlockHeight(blockHeight uint64) bool {
	return blockHeight >= params.GetFirstPoSBlockHeight()
}

func (params *DeSoParams) IsFinalPoWBlockHeight(blockHeight uint64) bool {
	return blockHeight == params.GetFinalPoWBlockHeight()
}

func (params *DeSoParams) GetFinalPoWBlockHeight() uint64 {
	return uint64(params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight - 1)
}

func (params *DeSoParams) GetFirstPoSBlockHeight() uint64 {
	return uint64(params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight)
}

func (params *DeSoParams) GetSnapshotBlockHeightPeriod(blockHeight uint64, currentSnapshotBlockHeightPeriod uint64) uint64 {
	if blockHeight < uint64(params.ForkHeights.ProofOfStake1StateSetupBlockHeight) {
		return params.DefaultPoWSnapshotBlockHeightPeriod
	}
	return currentSnapshotBlockHeightPeriod
}

// GenesisBlock defines the genesis block used for the DeSo mainnet and testnet
var (
	ArchitectPubKeyBase58Check = "BC1YLg3oh6Boj8e2boCo1vQCYHLk1rjsHF6jthBdvSw79bixQvKK6Qa"
	// This is the public key corresponding to the BitcoinBurnAddress on mainnet.
	BurnPubKeyBase58Check = "BC1YLjWBf2qnDJmi8HZzzCPeXqy4dCKq95oqqzerAyW8MUTbuXTb1QT"

	GenesisBlock = MsgDeSoBlock{
		Header: &MsgDeSoHeader{
			Version:               0,
			PrevBlockHash:         &BlockHash{},
			TransactionMerkleRoot: mustDecodeHexBlockHash("4b71d103dd6fff1bd6110bc8ed0a2f3118bbe29a67e45c6c7d97546ad126906f"),
			TstampNanoSecs:        SecondsToNanoSeconds(1610948544),
			Height:                uint64(0),
			Nonce:                 uint64(0),
		},
		Txns: []*MsgDeSoTxn{
			{
				TxInputs: []*DeSoInput{},
				// The outputs in the genesis block aren't actually used by anything, but
				// including them helps our block explorer return the genesis transactions
				// without needing an explicit special case.
				TxOutputs: SeedBalances,
				// TODO: Pick a better string
				TxnMeta: &BlockRewardMetadataa{
					ExtraData: []byte(
						"They came here, to the New World. World 2.0, version 1776."),
				},
				// A signature is not required for BLOCK_REWARD transactions since they
				// don't spend anything.
			},
		},
	}
	GenesisBlockHashHex = "5567c45b7b83b604f9ff5cb5e88dfc9ad7d5a1dd5818dd19e6d02466f47cbd62"
	GenesisBlockHash    = mustDecodeHexBlockHash(GenesisBlockHashHex)
)

func GetParamUpdaterPublicKeys(blockHeight uint32, params *DeSoParams) map[PkMapKey]bool {
	// We use legacy paramUpdater values before this block height
	var paramUpdaterKeys map[PkMapKey]bool
	if blockHeight < params.ForkHeights.ParamUpdaterRefactorBlockHeight {
		paramUpdaterKeys = map[PkMapKey]bool{
			// 19Hg2mAJUTKFac2F2BBpSEm7BcpkgimrmD
			MakePkMapKey(MustBase58CheckDecode(ArchitectPubKeyBase58Check)):                                true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLiXwGTte8oXEEVzm4zqtDpGRx44Y4rqbeFeAs5MnzsmqT5RcqkW")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLgGLKjuHUFZZQcNYrdWRrHsDKUofd9MSxDq4NY53x7vGt4H32oZ")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLj8UkNMbCsmTUTx5Z2bhtp8q86csDthRmK6zbYstjjbS5eHoGkr")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLgD1f7yw7Ue8qQiW7QMBSm6J7fsieK5rRtyxmWqL2Ypra2BAToc")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLfz4GH3Gfj6dCtBi8bNdNTbTdcibk8iCZS75toUn4UKZaTJnz9y")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLfoSyJWKjHGnj5ZqbSokC3LPDNBMDwHX3ehZDCA3HVkFNiPY5cQ")): true,
		}
	} else {
		paramUpdaterKeys = map[PkMapKey]bool{
			MakePkMapKey(MustBase58CheckDecode("BC1YLgKBcYwyWCqnBHKoJY2HX1sc38A7JuA2jMNEmEXfcRpc7D6Hyiu")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLfrtYZs4mCeSALnjTUZMdcwsWNHoNaG5gWWD5WyvRrWNTGWWq1q")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLiABrQ1P5pKXdm8S1vj1annx6D8Asku5CXX477dpwYXDamprpWd")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLfqYyePuSYPVFB2mdh9Dss7PJ9j5vJts87b9zGbVJhQDjCJNdjb")): true,
			MakePkMapKey(MustBase58CheckDecode("BC1YLjDmDtymghnMgAPmTCyykqhcNR19sgSS7pWNd36FXTZpUZNHypj")): true,
		}
	}

	// Add extra paramUpdater keys when we're in regtest mode. This is useful in
	// tests where we need to mess with things.
	for kk, vv := range params.ExtraRegtestParamUpdaterKeys {
		paramUpdaterKeys[kk] = vv
	}

	return paramUpdaterKeys
}

// GlobalDeSoParams is a global instance of DeSoParams that can be used inside nested functions, like encoders, without
// having to pass DeSoParams everywhere. It can be set when node boots. Testnet params are used as default.
// FIXME: This shouldn't be used a lot.
var GlobalDeSoParams = DeSoTestnetParams

var MainnetForkHeights = ForkHeights{
	DefaultHeight:                0,
	DeflationBombBlockHeight:     33783,
	SalomonFixBlockHeight:        uint32(15270),
	DeSoFounderRewardBlockHeight: uint32(21869),
	BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight: uint32(39713),
	ParamUpdaterProfileUpdateFixBlockHeight:              uint32(39713),
	UpdateProfileFixBlockHeight:                          uint32(46165),
	BrokenNFTBidsFixBlockHeight:                          uint32(46917),
	DeSoDiamondsBlockHeight:                              uint32(52112),
	NFTTransferOrBurnAndDerivedKeysBlockHeight:           uint32(60743),

	// Mon Jan 24 2022 @ 12pm PST
	DeSoV3MessagesBlockHeight:     uint32(98474),
	BuyNowAndNFTSplitsBlockHeight: uint32(98474),
	DAOCoinBlockHeight:            uint32(98474),

	ExtraDataOnEntriesBlockHeight:            uint32(130901),
	DerivedKeySetSpendingLimitsBlockHeight:   uint32(130901),
	DerivedKeyTrackSpendingLimitsBlockHeight: uint32(130901),
	DAOCoinLimitOrderBlockHeight:             uint32(130901),

	// Fri Jun 9 2022 @ 12pm PT
	DerivedKeyEthSignatureCompatibilityBlockHeight: uint32(137173),
	OrderBookDBFetchOptimizationBlockHeight:        uint32(137173),

	ParamUpdaterRefactorBlockHeight: uint32(141193),

	// Mon Sept 19 2022 @ 12pm PST
	DeSoUnlimitedDerivedKeysBlockHeight: uint32(166066),

	// Mon Feb 6 2023 @ 9am PST
	AssociationsAndAccessGroupsBlockHeight: uint32(205386),

	// Wed Mar 8 2023 @ 5pm PST
	AssociationsDerivedKeySpendingLimitBlockHeight: uint32(213487),

	// Mon Apr 24 2023 @ 9am PST
	BalanceModelBlockHeight: uint32(226839),

	// FIXME: set to real block height when ready
	ProofOfStake1StateSetupBlockHeight: uint32(math.MaxUint32),

	// FIXME: set to real block height when ready
	ProofOfStake2ConsensusCutoverBlockHeight: uint32(math.MaxUint32),

	// FIXME: set to real block height when ready
	LockupsBlockHeight: uint32(math.MaxUint32),

	// Be sure to update EncoderMigrationHeights as well via
	// GetEncoderMigrationHeights if you're modifying schema.
}

// DeSoMainnetParams defines the DeSo parameters for the mainnet.
var DeSoMainnetParams = DeSoParams{
	NetworkType:        NetworkType_MAINNET,
	ProtocolVersion:    ProtocolVersion1,
	MinProtocolVersion: 1,
	UserAgent:          "Architect",
	DNSSeeds: []string{
		"deso.coinbase.com",
		"deso.gemini.com",
		"deso.kraken.com",
		"deso.bitstamp.com",
		"deso.bitfinex.com",
		"deso.binance.com",
		"deso.hbg.com",
		"deso.okex.com",
		"deso.bithumb.com",
		"deso.upbit.com",
	},
	DNSSeedGenerators: [][]string{
		{
			"deso-seed-",
			".io",
		},
	},

	GenesisBlock:        &GenesisBlock,
	GenesisBlockHashHex: GenesisBlockHashHex,
	// This is used as the starting difficulty for the chain.
	MinDifficultyTargetHex: "000001FFFF000000000000000000000000000000000000000000000000000000",

	// Run with --v=2 and look for "cum work" output from miner.go
	MinChainWorkHex: "000000000000000000000000000000000000000000000000006314f9a85a949b",

	MaxTipAgePoW: 24 * time.Hour,
	MaxTipAgePoS: time.Hour,

	// ===================================================================================
	// Mainnet Bitcoin config
	// ===================================================================================
	BitcoinBtcdParams:  &chaincfg.MainNetParams,
	BitcoinBurnAddress: "1PuXkbwqqwzEYo9SPGyAihAge3e9Lc71b",

	// We use a start node that is near the tip of the Bitcoin header chain. Doing
	// this allows us to bootstrap Bitcoin transactions much more quickly without
	// compromising on security because, if this node ends up not being on the best
	// chain one day (which would be completely ridiculous anyhow because it would mean that
	// days or months of bitcoin transactions got reverted), our code will still be
	// able to robustly switch to an alternative chain that has more work. It's just
	// much faster if the best chain is the one that has this start node in it (similar
	// to the --assumevalid Bitcoin flag).
	//
	// Process for generating this config:
	// - Find a node config from the scripts/nodes folder (we used n0)
	// - Make sure the logging for bitcoin_manager is set to 2. --vmodule="bitcoin_manager=2"
	// - Run the node config (./n0)
	// - A line should print every time there's a difficulty adjustment with the parameters
	//   required below (including "DiffBits"). Just copy those into the below and
	//   everything should work.
	// - Oh and you might have to set BitcoinMinChainWorkHex to something lower/higher. The
	//   value should equal the amount of work it takes to get from whatever start node you
	//   choose and the tip. This is done by running once, letting it fail, and then rerunning
	//   with the value it outputs.
	BitcoinStartBlockNode: NewBlockNode(
		nil,
		mustDecodeHexBlockHashBitcoin("000000000000000000092d577cc673bede24b6d7199ee69c67eeb46c18fc978c"),
		// Note the height is always one greater than the parent node.
		653184,
		_difficultyBitsToHash(386798414),
		// CumWork shouldn't matter.
		big.NewInt(0),
		// We are bastardizing the DeSo header to store Bitcoin information here.
		&MsgDeSoHeader{
			TstampNanoSecs: SecondsToNanoSeconds(1602950620),
			Height:         0,
		},
		StatusBitcoinHeaderValidated,
	),

	BitcoinExchangeFeeBasisPoints: 10,
	BitcoinDoubleSpendWaitSeconds: 5.0,
	ServerMessageChannelSize:      uint32(100),
	DeSoNanosPurchasedAtGenesis:   uint64(6000000000000000),
	DefaultSocketPort:             uint16(17000),
	DefaultJSONPort:               uint16(17001),

	DialTimeout:                   30 * time.Second,
	VersionNegotiationTimeout:     30 * time.Second,
	VerackNegotiationTimeout:      30 * time.Second,
	NetworkManagerRefreshDuration: 1 * time.Second,

	MaxAddressesToBroadcast: 10,

	BlockRewardMaturity: time.Hour * 3,

	V1DifficultyAdjustmentFactor: 10,

	// Use a five-minute block time. Although a shorter block time seems like
	// it would improve the user experience, the reality is that zero-confirmation
	// transactions can usually be relied upon to give the user the illusion of
	// instant gratification (particularly since we implement a limited form of
	// RBF that makes it difficult to reverse transactions once they're in the
	// mempool of nodes). Moreover, longer block times mean we require fewer
	// headers to be downloaded by light clients in the long run, which is a
	// big win in terms of performance.
	TimeBetweenBlocks: 5 * time.Minute,
	// We retarget the difficulty every day. Note this value must
	// ideally be evenly divisible by TimeBetweenBlocks.
	TimeBetweenDifficultyRetargets: 24 * time.Hour,
	// Difficulty can't decrease to below 25% of its previous value or increase
	// to above 400% of its previous value.
	MaxDifficultyRetargetFactor: 4,
	Base58PrefixPublicKey:       [3]byte{0xcd, 0x14, 0x0},
	Base58PrefixPrivateKey:      [3]byte{0x35, 0x0, 0x0},

	// Reject blocks that are more than two hours in the future.
	MaxTstampOffsetSeconds: 2 * 60 * 60,

	// We use a max block size of 16MB. This translates to 100-200 posts per
	// second depending on the size of the post, which should support around
	// ten million active users. We compute this by taking Twitter, which averages
	// 6,000 posts per second at 300M daus => 10M/300M*6,000=200 posts per second. This
	// generates about 1.6TB per year of data, which means that nodes will
	// have to have a lot of space. This seems fine, however,
	// because space is cheap and it's easy to spin up a cloud machine with
	// tens of terabytes of space.
	MaxBlockSizeBytesPoW: 16000000,

	// We set this to be lower initially to avoid winding up with really big
	// spam blocks in the event someone tries to abuse the initially low min
	// fee rates.
	MinerMaxBlockSizeBytes: 2000000,

	// This takes about ten seconds on a reasonable CPU, which makes sense given
	// a 10 minute block time.
	MiningIterationsPerCycle: 95000,

	DefaultPoWSnapshotBlockHeightPeriod: 1000,

	MaxUsernameLengthBytes: MaxUsernameLengthBytes,

	MaxUserDescriptionLengthBytes: 20000,

	MaxProfilePicLengthBytes: 20000,
	MaxProfilePicDimensions:  100,

	// MaxPrivateMessageLengthBytes is the maximum number of bytes of encrypted
	// data a private message is allowed to include in an PrivateMessage transaction.
	MaxPrivateMessageLengthBytes: 10000,

	// MaxNewMessageLengthBytes is the maximum number of bytes of encrypted
	// data a new message is allowed to include in an NewMessage transaction.
	MaxNewMessageLengthBytes: 10000,

	// Set the stake fee to 10%
	StakeFeeBasisPoints: 10 * 100,
	// TODO(performance): We're currently storing posts using HTML, which is
	// basically 2x as verbose as it needs to be for no reason. We should
	// consider storing stuff as markdown instead, which we can do with
	// the richtext editor thing that we have.
	MaxPostBodyLengthBytes: 20000,
	MaxPostSubLengthBytes:  140,
	// 10x is the max for the truly highly motivated individuals.
	MaxStakeMultipleBasisPoints: 10 * 100 * 100,
	// 100% is the max creator percentage. Not sure why you'd buy such a coin
	// but whatever.
	MaxCreatorBasisPoints:    100 * 100,
	MaxNFTRoyaltyBasisPoints: 100 * 100,

	// Use a canonical set of seed transactions.
	SeedTxns: SeedTxns,

	// Set some seed balances if desired
	SeedBalances: SeedBalances,

	// Just charge one basis point on creator coin trades for now.
	CreatorCoinTradeFeeBasisPoints: 1,
	// Note that Uniswap is quadratic (i.e. its price equation is
	// - price ~= currentCreatorCoinSupply^2,
	// and we think quadratic makes sense in this context as well.
	CreatorCoinSlope:        NewFloat().SetFloat64(0.003),
	CreatorCoinReserveRatio: NewFloat().SetFloat64(0.3333333),

	// 10 was seen as a threshold reachable in almost all transaction.
	// It's just high enough where you avoid drifting creating coin
	// reserve ratios.
	CreatorCoinAutoSellThresholdNanos: uint64(10),

	// Unstaked stake can be unlocked after a minimum of N elapsed epochs.
	DefaultStakeLockupEpochDuration: uint64(3),

	// Jailed validators can be unjailed after a minimum of N elapsed epochs.
	DefaultValidatorJailEpochDuration: uint64(3),

	// The max number of validators included in a leader schedule.
	DefaultLeaderScheduleMaxNumValidators: uint64(100),

	// The max number of validators included in a validator set for any given epoch.
	DefaultValidatorSetMaxNumValidators: uint64(1000),

	// The max number of stakes included in a staking rewards distribution every epoch.
	DefaultStakingRewardsMaxNumStakes: uint64(10000),

	// Staking reward APY is defaulted to 0% to be safe.
	DefaultStakingRewardsAPYBasisPoints: uint64(0),

	// The number of blocks in one epoch. This number is tuned to result in roughly 10 epochs
	// per day given a 10-minute block time on mainnet when running PoW. The number is tuned
	// for PoW because epoch transitions begin on PoW before the chain transitions to PoS.
	DefaultEpochDurationNumBlocks: uint64(144),

	// The number of epochs before an inactive validator is jailed
	DefaultJailInactiveValidatorGracePeriodEpochs: uint64(48),

	// The number of nanoseconds from the current timestamp that we will allow a PoS block to be submitted.
	DefaultBlockTimestampDriftNanoSecs: (time.Minute * 10).Nanoseconds(),

	// The rate of growth of the fee bucket ranges.
	DefaultFeeBucketGrowthRateBasisPoints: uint64(1000),

	// The maximum number of vested lockup intersections in a lockup transaction.
	DefaultMaximumVestedIntersectionsPerLockupTransaction: 1000,

	// The maximum size of the mempool in bytes.
	DefaultMempoolMaxSizeBytes: 3 * 1024 * 1024 * 1024, // 3GB

	// The number of future blocks to consider when estimating the mempool fee.
	DefaultMempoolFeeEstimatorNumMempoolBlocks: 1,

	// The number of past blocks to consider when estimating the mempool fee.
	DefaultMempoolFeeEstimatorNumPastBlocks: 50,

	// The maximum size of blocks for PoS.
	DefaultMaxBlockSizeBytesPoS: 32000, // 32KB TODO: verify this is a sane value.

	// The soft maximum size of blocks for PoS.
	DefaultSoftMaxBlockSizeBytesPoS: 16000, // 16KB TODO: verify this is a sane value.

	// The maximum size for a single txn in PoS.
	DefaultMaxTxnSizeBytesPoS: 25000, // 25KB TODO: verify this is a sane value.

	// The interval between producing blocks.
	DefaultBlockProductionIntervalMillisecondsPoS: 1500, // 1.5s TODO: verify this is a sane value.

	// The interval between timing out a view.
	DefaultTimeoutIntervalMillisecondsPoS: 30000, // 30s TODO: verify this is a sane value.

	// The peer handshake certificate timeout.
	HandshakeTimeoutMicroSeconds: uint64(900000000),

	// DisableNetworkManagerRoutines is a testing flag that disables the network manager routines.
	DisableNetworkManagerRoutines: false,

	ForkHeights:                 MainnetForkHeights,
	EncoderMigrationHeights:     GetEncoderMigrationHeights(&MainnetForkHeights),
	EncoderMigrationHeightsList: GetEncoderMigrationHeightsList(&MainnetForkHeights),
}

func mustDecodeHexBlockHashBitcoin(ss string) *BlockHash {
	hash, err := chainhash.NewHashFromStr(ss)
	if err != nil {
		panic(any(errors.Wrapf(err, "mustDecodeHexBlockHashBitcoin: Problem decoding block hash: %v", ss)))
	}
	return (*BlockHash)(hash)
}

func MustDecodeHexBlockHash(ss string) *BlockHash {
	return mustDecodeHexBlockHash(ss)
}

func mustDecodeHexBlockHash(ss string) *BlockHash {
	bb, err := hex.DecodeString(ss)
	if err != nil {
		log.Fatalf("Problem decoding hex string to bytes: (%s): %v", ss, err)
	}
	if len(bb) != 32 {
		log.Fatalf("mustDecodeHexBlockHash: Block hash has length (%d) but should be (%d)", len(bb), 32)
	}
	ret := BlockHash{}
	copy(ret[:], bb)
	return &ret
}

var TestnetForkHeights = ForkHeights{
	// Get testnet height from here:
	// - https://explorer.deso.org/?query-node=https:%2F%2Ftest.deso.org

	// Initially, testnet fork heights were the same as mainnet heights
	// This changed when we spun up a real testnet that runs independently
	DefaultHeight:                0,
	DeflationBombBlockHeight:     33783,
	SalomonFixBlockHeight:        uint32(15270),
	DeSoFounderRewardBlockHeight: uint32(21869),
	BuyCreatorCoinAfterDeletedBalanceEntryFixBlockHeight: uint32(39713),
	ParamUpdaterProfileUpdateFixBlockHeight:              uint32(39713),
	UpdateProfileFixBlockHeight:                          uint32(46165),
	BrokenNFTBidsFixBlockHeight:                          uint32(46917),
	DeSoDiamondsBlockHeight:                              uint32(52112),
	NFTTransferOrBurnAndDerivedKeysBlockHeight:           uint32(60743),

	// Flags after this point can differ from mainnet

	// Thu Jan 20 2022 @ 12pm PST
	DeSoV3MessagesBlockHeight:     uint32(97322),
	BuyNowAndNFTSplitsBlockHeight: uint32(97322),
	DAOCoinBlockHeight:            uint32(97322),

	// Wed Apr 20 2022 @ 9am ET
	ExtraDataOnEntriesBlockHeight:          uint32(304087),
	DerivedKeySetSpendingLimitsBlockHeight: uint32(304087),
	// Add 18h for the spending limits to be checked, since this is how we're
	// going to do it on mainnet. Testnet produces 60 blocks per hour.
	DerivedKeyTrackSpendingLimitsBlockHeight: uint32(304087 + 18*60),
	DAOCoinLimitOrderBlockHeight:             uint32(304087),

	// Thu Jun 9 2022 @ 11:59pm PT
	DerivedKeyEthSignatureCompatibilityBlockHeight: uint32(360584),
	OrderBookDBFetchOptimizationBlockHeight:        uint32(360584),

	ParamUpdaterRefactorBlockHeight: uint32(373536),

	// Tues Sept 13 2022 @ 10am PT
	DeSoUnlimitedDerivedKeysBlockHeight: uint32(467217),

	// Tues Jan 24 2023 @ 1pm PT
	AssociationsAndAccessGroupsBlockHeight: uint32(596555),

	// Mon Mar 6 2023 @ 7pm PT
	AssociationsDerivedKeySpendingLimitBlockHeight: uint32(642270),

	// Tues Apr 11 2023 @ 5pm PT
	BalanceModelBlockHeight: uint32(683058),

	// Tues May 23 2023 @ 9am PT
	BlockRewardPatchBlockHeight: uint32(729753),

	// FIXME: set to real block height when ready
	ProofOfStake1StateSetupBlockHeight: uint32(math.MaxUint32),

	// FIXME: set to real block height when ready
	ProofOfStake2ConsensusCutoverBlockHeight: uint32(math.MaxUint32),

	// FIXME: set to real block height when ready
	LockupsBlockHeight: uint32(math.MaxUint32),

	// Be sure to update EncoderMigrationHeights as well via
	// GetEncoderMigrationHeights if you're modifying schema.
}

// DeSoTestnetParams defines the DeSo parameters for the testnet.
var DeSoTestnetParams = DeSoParams{
	NetworkType:        NetworkType_TESTNET,
	ProtocolVersion:    ProtocolVersion0,
	MinProtocolVersion: 0,
	UserAgent:          "Architect",
	DNSSeeds: []string{
		"dorsey.bitclout.com",
	},
	DNSSeedGenerators: [][]string{},

	// ===================================================================================
	// Testnet Bitcoin config
	// ===================================================================================
	BitcoinBtcdParams:             &chaincfg.TestNet3Params,
	BitcoinBurnAddress:            "mhziDsPWSMwUqvZkVdKY92CjesziGP3wHL",
	BitcoinExchangeFeeBasisPoints: 10,
	BitcoinDoubleSpendWaitSeconds: 5.0,
	ServerMessageChannelSize:      uint32(100),
	DeSoNanosPurchasedAtGenesis:   uint64(6000000000000000),

	// See comment in mainnet config.
	BitcoinStartBlockNode: NewBlockNode(
		nil,
		mustDecodeHexBlockHashBitcoin("000000000000003aae8fb976056413aa1d863eb5bee381ff16c9642283b1da1a"),
		1897056,
		_difficultyBitsToHash(424073553),

		// CumWork: We set the work of the start node such that, when added to all of the
		// blocks that follow it, it hurdles the min chain work.
		big.NewInt(0),
		// We are bastardizing the DeSo header to store Bitcoin information here.
		&MsgDeSoHeader{
			TstampNanoSecs: SecondsToNanoSeconds(1607659152),
			Height:         0,
		},
		StatusBitcoinHeaderValidated,
	),

	// ===================================================================================
	// Testnet socket config
	// ===================================================================================
	DefaultSocketPort: uint16(18000),
	DefaultJSONPort:   uint16(18001),

	DialTimeout:                   30 * time.Second,
	VersionNegotiationTimeout:     30 * time.Second,
	VerackNegotiationTimeout:      30 * time.Second,
	NetworkManagerRefreshDuration: 1 * time.Second,

	MaxAddressesToBroadcast: 10,

	GenesisBlock:        &GenesisBlock,
	GenesisBlockHashHex: GenesisBlockHashHex,

	// Use a faster block time in the testnet.
	TimeBetweenBlocks: 1 * time.Minute,
	// Use a very short difficulty retarget period in the testnet.
	TimeBetweenDifficultyRetargets: 3 * time.Minute,
	// This is used as the starting difficulty for the chain.
	MinDifficultyTargetHex: "0090000000000000000000000000000000000000000000000000000000000000",
	// Minimum amount of work a valid chain needs to have. Useful for preventing
	// disk-fill attacks, among other things.
	//MinChainWorkHex: "000000000000000000000000000000000000000000000000000000011883b96c",
	MinChainWorkHex: "0000000000000000000000000000000000000000000000000000000000000000",

	// TODO: Set to one day when we launch the testnet. In the meantime this value
	// is more useful for local testing.
	MaxTipAgePoW: time.Hour * 24,
	MaxTipAgePoS: time.Hour,

	// Difficulty can't decrease to below 50% of its previous value or increase
	// to above 200% of its previous value.
	MaxDifficultyRetargetFactor: 2,
	// Miners need to wait some time before spending their block reward.
	BlockRewardMaturity: 5 * time.Minute,

	V1DifficultyAdjustmentFactor: 10,

	// Reject blocks that are more than two hours in the future.
	MaxTstampOffsetSeconds: 2 * 60 * 60,

	// We use a max block size of 1MB. This seems to work well for BTC and
	// most of our data doesn't need to be stored on the blockchain anyway.
	MaxBlockSizeBytesPoW: 1000000,

	// We set this to be lower initially to avoid winding up with really big
	// spam blocks in the event someone tries to abuse the initially low min
	// fee rates.
	MinerMaxBlockSizeBytes: 1000000,

	Base58PrefixPublicKey:  [3]byte{0x11, 0xc2, 0x0},
	Base58PrefixPrivateKey: [3]byte{0x4f, 0x6, 0x1b},

	MiningIterationsPerCycle: 9500,

	DefaultPoWSnapshotBlockHeightPeriod: 1000,
	// deso
	MaxUsernameLengthBytes: MaxUsernameLengthBytes,

	MaxUserDescriptionLengthBytes: 20000,

	MaxProfilePicLengthBytes: 20000,
	MaxProfilePicDimensions:  100,

	// MaxPrivateMessageLengthBytes is the maximum number of bytes of encrypted
	// data a private message is allowed to include in an PrivateMessage transaction.
	MaxPrivateMessageLengthBytes: 10000,

	// MaxNewMessageLengthBytes is the maximum number of bytes of encrypted
	// data a new message is allowed to include in an NewMessage transaction.
	MaxNewMessageLengthBytes: 10000,

	// Set the stake fee to 5%
	StakeFeeBasisPoints: 5 * 100,
	// TODO(performance): We're currently storing posts using HTML, which
	// basically 2x as verbose as it needs to be for basically no reason.
	// We should consider storing stuff as markdown instead, which we can
	// do with the richtext editor thing that we have.
	MaxPostBodyLengthBytes: 50000,
	MaxPostSubLengthBytes:  140,
	// 10x is the max for the truly highly motivated individuals.
	MaxStakeMultipleBasisPoints: 10 * 100 * 100,
	// 100% is the max creator percentage. Not sure why you'd buy such a coin
	// but whatever.
	MaxCreatorBasisPoints:    100 * 100,
	MaxNFTRoyaltyBasisPoints: 100 * 100,

	// Use a canonical set of seed transactions.
	SeedTxns: TestSeedTxns,

	// Set some seed balances if desired
	// Note: For now these must be the same as mainnet because GenesisBlock is the same
	SeedBalances: SeedBalances,

	// Just charge one basis point on creator coin trades for now.
	CreatorCoinTradeFeeBasisPoints: 1,
	// Note that Uniswap is quadratic (i.e. its price equation is
	// - price ~= currentCreatorCoinSupply^2,
	// and we think quadratic makes sense in this context as well.
	CreatorCoinSlope:        NewFloat().SetFloat64(0.003),
	CreatorCoinReserveRatio: NewFloat().SetFloat64(0.3333333),

	// 10 was seen as a threshold reachable in almost all transaction.
	// It's just high enough where you avoid drifting creating coin
	// reserve ratios.
	CreatorCoinAutoSellThresholdNanos: uint64(10),

	// Unstaked stake can be unlocked after a minimum of N elapsed epochs.
	DefaultStakeLockupEpochDuration: uint64(3),

	// Jailed validators can be unjailed after a minimum of N elapsed epochs.
	DefaultValidatorJailEpochDuration: uint64(3),

	// The max number of validators included in a leader schedule.
	DefaultLeaderScheduleMaxNumValidators: uint64(100),

	// The max number of validators included in a validator set for any given epoch.
	DefaultValidatorSetMaxNumValidators: uint64(1000),

	// The max number of stakes included in a staking rewards distribution every epoch.
	DefaultStakingRewardsMaxNumStakes: uint64(10000),

	// Staking reward APY is defaulted to 0% to be safe.
	DefaultStakingRewardsAPYBasisPoints: uint64(0),

	// The number of blocks in one epoch. This number is tuned to result in roughly 10 epochs
	// per day given a 10-minute block time on testnet when running PoW. The number is tuned
	// for PoW because epoch transitions begin on PoW before the chain transitions to PoS.
	DefaultEpochDurationNumBlocks: uint64(144),

	// The number of epochs before an inactive validator is jailed
	DefaultJailInactiveValidatorGracePeriodEpochs: uint64(48),

	// The number of nanoseconds from the current timestamp that we will allow a PoS block to be submitted.
	DefaultBlockTimestampDriftNanoSecs: (time.Minute * 10).Nanoseconds(),

	// The rate of growth of the fee bucket ranges.
	DefaultFeeBucketGrowthRateBasisPoints: uint64(1000),

	// The maximum number of vested lockup intersections in a lockup transaction.
	DefaultMaximumVestedIntersectionsPerLockupTransaction: 1000,

	// The maximum size of the mempool in bytes.
	DefaultMempoolMaxSizeBytes: 3 * 1024 * 1024 * 1024, // 3GB

	// The number of future blocks to consider when estimating the mempool fee.
	DefaultMempoolFeeEstimatorNumMempoolBlocks: 1,

	// The number of past blocks to consider when estimating the mempool fee.
	DefaultMempoolFeeEstimatorNumPastBlocks: 50,

	// The maximum size of blocks for PoS.
	DefaultMaxBlockSizeBytesPoS: 32000, // 32KB TODO: verify this is a sane value.

	// The soft maximum size of blocks for PoS.
	DefaultSoftMaxBlockSizeBytesPoS: 16000, // 16KB TODO: verify this is a sane value.

	// The maximum size for a single txn in PoS.
	DefaultMaxTxnSizeBytesPoS: 25000, // 25KB TODO: verify this is a sane value.

	// The interval between producing blocks.
	DefaultBlockProductionIntervalMillisecondsPoS: 1500, // 1.5s TODO: verify this is a sane value.

	// The interval between timing out a view.
	DefaultTimeoutIntervalMillisecondsPoS: 30000, // 30s TODO: verify this is a sane value.

	// The peer handshake certificate timeout.
	HandshakeTimeoutMicroSeconds: uint64(900000000),

	// DisableNetworkManagerRoutines is a testing flag that disables the network manager routines.
	DisableNetworkManagerRoutines: false,

	ForkHeights:                 TestnetForkHeights,
	EncoderMigrationHeights:     GetEncoderMigrationHeights(&TestnetForkHeights),
	EncoderMigrationHeightsList: GetEncoderMigrationHeightsList(&TestnetForkHeights),
}

// GetDataDir gets the user data directory where we store files
// in a cross-platform way.
func GetDataDir(params *DeSoParams) string {
	configDirs := configdir.New(
		ConfigDirVendorName, ConfigDirAppName)
	dirString := configDirs.QueryFolders(configdir.Global)[0].Path
	dataDir := filepath.Join(dirString, params.NetworkType.String())
	if err := os.MkdirAll(dataDir, os.ModePerm); err != nil {
		log.Fatalf("GetDataDir: Could not create data directories (%s): %v", dataDir, err)
	}
	return dataDir
}

func VersionByteToMigrationHeight(version byte, params *DeSoParams) (_blockHeight uint64) {
	for _, migrationHeight := range params.EncoderMigrationHeightsList {
		if migrationHeight.Version == version {
			return migrationHeight.Height
		}
	}
	return 0
}

// Defines keys that may exist in a transaction's ExtraData map
const (
	// Key in transaction's extra data map that points to a post that the current transaction is reposting
	RepostedPostHash = "RecloutedPostHash"
	// Key in transaction's extra map -- The presence of this key indicates that this post is a repost with a quote.
	IsQuotedRepostKey = "IsQuotedReclout"
	// Key in transaction's extra data map that freezes a post rendering it immutable.
	IsFrozenKey = "IsFrozen"

	// Keys for a GlobalParamUpdate transaction's extra data map.
	USDCentsPerBitcoinKey                             = "USDCentsPerBitcoin"
	MinNetworkFeeNanosPerKBKey                        = "MinNetworkFeeNanosPerKB"
	CreateProfileFeeNanosKey                          = "CreateProfileFeeNanos"
	CreateNFTFeeNanosKey                              = "CreateNFTFeeNanos"
	MaxCopiesPerNFTKey                                = "MaxCopiesPerNFT"
	MaxNonceExpirationBlockHeightOffsetKey            = "MaxNonceExpirationBlockHeightOffset"
	ForbiddenBlockSignaturePubKeyKey                  = "ForbiddenBlockSignaturePubKey"
	StakeLockupEpochDurationKey                       = "StakeLockupEpochDuration"
	ValidatorJailEpochDurationKey                     = "ValidatorJailEpochDuration"
	LeaderScheduleMaxNumValidatorsKey                 = "LeaderScheduleMaxNumValidators"
	ValidatorSetMaxNumValidatorsKey                   = "ValidatorSetMaxNumValidators"
	StakingRewardsMaxNumStakesKey                     = "StakingRewardsMaxNumStakes"
	StakingRewardsAPYBasisPointsKey                   = "StakingRewardsAPYBasisPoints"
	EpochDurationNumBlocksKey                         = "EpochDurationNumBlocks"
	JailInactiveValidatorGracePeriodEpochsKey         = "JailInactiveValidatorGracePeriodEpochs"
	MaximumVestedIntersectionsPerLockupTransactionKey = "MaximumVestedIntersectionsPerLockupTransaction"
	FeeBucketGrowthRateBasisPointsKey                 = "FeeBucketGrowthRateBasisPointsKey"
	BlockTimestampDriftNanoSecsKey                    = "BlockTimestampDriftNanoSecs"
	MempoolMaxSizeBytesKey                            = "MempoolMaxSizeBytes"
	MempoolFeeEstimatorNumMempoolBlocksKey            = "MempoolFeeEstimatorNumMempoolBlocks"
	MempoolFeeEstimatorNumPastBlocksKey               = "MempoolFeeEstimatorNumPastBlocks"
	MaxBlockSizeBytesPoSKey                           = "MaxBlockSizeBytesPoS"
	SoftMaxBlockSizeBytesPoSKey                       = "SoftMaxBlockSizeBytesPoS"
	MaxTxnSizeBytesPoSKey                             = "MaxTxnSizeBytesPoS"
	BlockProductionIntervalPoSKey                     = "BlockProductionIntervalPoS"
	TimeoutIntervalPoSKey                             = "TimeoutIntervalPoS"

	DiamondLevelKey    = "DiamondLevel"
	DiamondPostHashKey = "DiamondPostHash"

	// Atomic Transaction Keys
	AtomicTxnsChainLength    = "AtmcChnLen"
	NextAtomicTxnPreHash     = "NxtAtmcHsh"
	PreviousAtomicTxnPreHash = "PrvAtmcHsh"

	// Key in transaction's extra data map containing the derived key used in signing the txn.
	DerivedPublicKey = "DerivedPublicKey"

	// Messaging keys
	MessagingPublicKey             = "MessagingPublicKey"
	SenderMessagingPublicKey       = "SenderMessagingPublicKey"
	SenderMessagingGroupKeyName    = "SenderMessagingGroupKeyName"
	RecipientMessagingPublicKey    = "RecipientMessagingPublicKey"
	RecipientMessagingGroupKeyName = "RecipientMessagingGroupKeyName"

	// Key in transaction's extra data map. If it is there, the NFT is a "Buy Now" NFT and this is the Buy Now Price
	BuyNowPriceKey = "BuyNowPriceNanos"

	// Key in transaction's extra data map. If present, the value represents a map of pkid to basis points representing
	// the amount of royalties the pkid should receive upon sale of this NFT.
	DESORoyaltiesMapKey = "DESORoyaltiesMap"

	// Key in transaction's extra data map. If present, the value represents a map of pkid to basis points representing
	// the amount of royalties that should be added to pkid's creator coin upon sale of this NFT.
	CoinRoyaltiesMapKey = "CoinRoyaltiesMap"

	// Used to distinguish v3 messages from previous iterations
	MessagesVersionString = "V"
	MessagesVersion1      = 1
	MessagesVersion2      = 2
	MessagesVersion3      = 3

	// Key in transaction's extra data map. If present, this value represents the Node ID of the running node. This maps
	// to the map of nodes in ./lib/nodes.go
	NodeSourceMapKey = "NodeSource"

	// TransactionSpendingLimit
	TransactionSpendingLimitKey = "TransactionSpendingLimit"
	DerivedKeyMemoKey           = "DerivedKeyMemo"

	// V3 Group Chat Messages ExtraData Key
	MessagingGroupOperationType = "MessagingGroupOperationType"
)

// Defines values that may exist in a transaction's ExtraData map
var (
	PostExtraDataConsensusKeys = [2]string{RepostedPostHash, IsQuotedRepostKey}
)

var (
	QuotedRepostVal    = []byte{1}
	NotQuotedRepostVal = []byte{0}
	IsFrozenPostVal    = []byte{1}
)

var (
	IsGraylisted   = []byte{1}
	IsBlacklisted  = []byte{1}
	NotGraylisted  = []byte{0}
	NotBlacklisted = []byte{0}
)

// InitialGlobalParamsEntry to be used before ParamUpdater creates the first update.
var (
	InitialGlobalParamsEntry = GlobalParamsEntry{
		// We initialize the USDCentsPerBitcoin to 0 so we can use the value set by the UPDATE_BITCOIN_USD_EXCHANGE_RATE.
		USDCentsPerBitcoin: 0,
		// We initialize the MinimumNetworkFeeNanosPerKB to 0 so we do not assess a minimum fee until specified by ParamUpdater.
		MinimumNetworkFeeNanosPerKB: 0,
		// We initialize the CreateProfileFeeNanos to 0 so we do not assess a fee to create a profile until specified by ParamUpdater.
		CreateProfileFeeNanos: 0,
		// We initialize the CreateNFTFeeNanos to 0 so we do not assess a fee to create an NFT until specified by ParamUpdater.
		CreateNFTFeeNanos: 0,
		MaxCopiesPerNFT:   0,
		// We initialize the FeeBucketGrowthRateBasisPoints to 1000, or equivalently, a multiplier of 1.1x.
		FeeBucketGrowthRateBasisPoints: 1000,
	}
)

// Define min / max possible values for GlobalParams.
const (
	// MinNetworkFeeNanosPerKBValue - Minimum value to which the minimum network fee per KB can be set.
	MinNetworkFeeNanosPerKBValue = 0
	// MaxNetworkFeeNanosPerKBValue - Maximum value to which the maximum network fee per KB can be set.
	MaxNetworkFeeNanosPerKBValue = 100 * NanosPerUnit
	// MinCreateProfileFeeNanos - Minimum value to which the create profile fee can be set.
	MinCreateProfileFeeNanos = 0
	// MaxCreateProfileFeeNanos - Maximum value to which the create profile fee can be set.
	MaxCreateProfileFeeNanos = 100 * NanosPerUnit
	// Min/MaxCreateNFTFeeNanos - Min/max value to which the create NFT fee can be set.
	MinCreateNFTFeeNanos = 0
	MaxCreateNFTFeeNanos = 100 * NanosPerUnit
	// Min/MaxMaxCopiesPerNFTNanos - Min/max value to which the create NFT fee can be set.
	MinMaxCopiesPerNFT = 1
	MaxMaxCopiesPerNFT = 10000
	// Messaging key constants
	MinMessagingKeyNameCharacters = 1
	MaxMessagingKeyNameCharacters = 32
	// Access group key constants
	MinAccessGroupKeyNameCharacters = 1
	MaxAccessGroupKeyNameCharacters = 32
	// Min/MaxMaxBlockSizeBytes - Min/max value to which the max block size can be set.
	MinMaxBlockSizeBytes = 1000     // 1kb TODO: Verify this is a sane value.
	MaxMaxBlockSizeBytes = 16000000 // 16MB TODO: Verify this is a sane value.
	// Min/MaxSoftMaxBlockSizeBytes - Min/max value to which the soft max block size can be set.
	MinSoftMaxBlockSizeBytes = 1000     // 1kb TODO: Verify this is a sane value.
	MaxSoftMaxBlockSizeBytes = 16000000 // 16MB TODO: Verify this is a sane value.
	// Min/MaxMaxTxnSizeBytes - Min/max value to which the max txn size can be set.
	MinMaxTxnSizeBytes = 1000     // 1kb TODO: Verify this is a sane value.
	MaxMaxTxnSizeBytes = 16000000 // 16MB TODO: Verify this is a sane value.
	// MinFeeBucketSize is the minimum size of a fee bucket that we'll allow global params to
	// be configured to compute. This is a safety measure to prevent the fee bucket from being
	// too small and causing issues with the mempool.
	MinFeeBucketSize = 10
	// Min/MaxBlockProductionIntervalMillisecondsPoS - Min/max value to which the block production interval can be set.
	MinBlockProductionIntervalMillisecondsPoS = 1000  // 1s TODO: Verify this is a sane value.
	MaxBlockProductionIntervalMillisecondsPoS = 10000 // 10s TODO: Verify this is a sane value.
	// Min/MaxTimeoutIntervalMillisecondsPoS - Min/max value to which the timeout interval can be set.
	MinTimeoutIntervalMillisecondsPoS = 1000  // 1s TODO: Verify this is a sane value.
	MaxTimeoutIntervalMillisecondsPoS = 60000 // 60s TODO: Verify this is a sane value.

	// DefaultMaxNonceExpirationBlockHeightOffset - default value to which the MaxNonceExpirationBlockHeightOffset
	// is set to before specified by ParamUpdater.
	DefaultMaxNonceExpirationBlockHeightOffset = 288

	// TODO: Are these fields needed?
	// Access group enumeration max recursion depth.
	MaxAccessGroupMemberEnumerationRecursionDepth = 10
	// Dm and group chat message entries paginated fetch max recursion depth
	MaxDmMessageRecursionDepth        = 10
	MaxGroupChatMessageRecursionDepth = 10
)

// Constants for UserAssociation and PostAssociation txn types.
const MaxAssociationTypeByteLength int = 64
const MaxAssociationValueByteLength int = 256
const AssociationTypeReservedPrefix = "DESO"
const AssociationNullTerminator = byte(0)

// The name of the txt file that contains whether the current Badger DB is using performance or default options.
const PerformanceDbOptsFileName = "performance_db_opts.txt"

// Constants used for staking rewards.
const MaxBasisPoints = uint64(10000)                     // 1e4
const NanoSecsPerYear = uint64(365) * 24 * 60 * 60 * 1e9 // 365 days * 24 hours * 60 minutes * 60 seconds * 1e9 nanoseconds

const BytesPerKB = 1000
