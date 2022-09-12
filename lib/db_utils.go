package lib

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/holiman/uint256"
	"io"
	"log"
	"math"
	"math/big"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

// This file contains all of the functions that interact with the database.

const (
	// BadgerDbFolder is the subfolder in the config dir where we
	// store the badgerdb database by default.
	BadgerDbFolder = "badgerdb"
	MaxPrefixLen   = 1
	// This string is added as a subdirectory of --data-dir flag that contains
	// everything our node is doing. We use it in order to force a "fresh sync"
	// of a node when making major updates. Not having this structure would
	// require node operators like Coinbase to change their --data-dir flag when
	// deploying a non-backwards-compatible version of the node.
	DBVersionString = "v-00000"
)

// -------------------------------------------------------------------------------------
// DB Prefixes
// -------------------------------------------------------------------------------------

// Prefixes is a static variable that contains all the parsed prefix_id values. We use the
// Prefixes var when fetching prefixes to avoid parsing the prefix_id tags every time.
var Prefixes = GetPrefixes()

// StatePrefixes is a static variable that allows us to quickly fetch state-related prefixes. We make
// the distinction between state and non-state prefixes for hyper sync, where the node is only syncing
// state prefixes. This significantly speeds up the syncing process and the node will still work properly.
var StatePrefixes = GetStatePrefixes()

type DBPrefixes struct {
	// The key prefixes for the key-value database. To store a particular
	// type of data, we create a key prefix and store all those types of
	// data with a key prefixed by that key prefix.
	// Bitcoin does a similar thing that you can see at this link:
	// https://bitcoin.stackexchange.com/questions/28168/what-are-the-keys-used-in-the-blockchain-leveldb-ie-what-are-the-keyvalue-pair

	// The prefix for the block index:
	// Key format: <prefix_id, hash BlockHash>
	// Value format: serialized MsgDeSoBlock
	PrefixBlockHashToBlock []byte `prefix_id:"[0]"`

	// The prefix for the node index that we use to reconstruct the block tree.
	// Storing the height in big-endian byte order allows us to read in all the
	// blocks in height-sorted order from the db and construct the block tree by connecting
	// nodes to their parents as we go.
	//
	// Key format: <prefix_id, height uint32 (big-endian), hash BlockHash>
	// Value format: serialized BlockNode
	PrefixHeightHashToNodeInfo        []byte `prefix_id:"[1]"`
	PrefixBitcoinHeightHashToNodeInfo []byte `prefix_id:"[2]"`

	// We store the hash of the node that is the current tip of the main chain.
	// This key is used to look it up.
	// Value format: BlockHash
	PrefixBestDeSoBlockHash []byte `prefix_id:"[3]"`

	PrefixBestBitcoinHeaderHash []byte `prefix_id:"[4]"`

	// Utxo table.
	// <prefix_id, txid BlockHash, output_index uint64> -> UtxoEntry
	PrefixUtxoKeyToUtxoEntry []byte `prefix_id:"[5]" is_state:"true"`
	// <prefix_id, pubKey [33]byte, utxoKey< txid BlockHash, index uint32 >> -> <>
	PrefixPubKeyUtxoKey []byte `prefix_id:"[7]" is_state:"true"`
	// The number of utxo entries in the database.
	PrefixUtxoNumEntries []byte `prefix_id:"[8]" is_state:"true"`
	// Utxo operations table.
	// This table contains, for each blockhash on the main chain, the UtxoOperations
	// that were applied by this block. To roll back the block, one must loop through
	// the UtxoOperations for a particular block backwards and invert them.
	//
	// <prefix_id, hash *BlockHash > -> < serialized []UtxoOperation using custom encoding >
	PrefixBlockHashToUtxoOperations []byte `prefix_id:"[9]"`
	// The below are mappings related to the validation of BitcoinExchange transactions.
	//
	// The number of nanos that has been purchased thus far.
	PrefixNanosPurchased []byte `prefix_id:"[10]" is_state:"true"`
	// How much Bitcoin is work in USD cents.
	PrefixUSDCentsPerBitcoinExchangeRate []byte `prefix_id:"[27]" is_state:"true"`
	// <prefix_id, key> -> <GlobalParamsEntry encoded>
	PrefixGlobalParams []byte `prefix_id:"[40]" is_state:"true"`

	// The prefix for the Bitcoin TxID map. If a key is set for a TxID that means this
	// particular TxID has been processed as part of a BitcoinExchange transaction. If
	// no key is set for a TxID that means it has not been processed (and thus it can be
	// used to create new nanos).
	// <prefix_id, BitcoinTxID BlockHash> -> <nothing>
	PrefixBitcoinBurnTxIDs []byte `prefix_id:"[11]" is_state:"true"`
	// Messages are indexed by the public key of their senders and receivers. If
	// a message sends from pkFrom to pkTo then there will be two separate entries,
	// one for pkFrom and one for pkTo. The exact format is as follows:
	// <public key (33 bytes) || uint64 big-endian> -> <MessageEntry>
	PrefixPublicKeyTimestampToPrivateMessage []byte `prefix_id:"[12]" is_state:"true"`

	// Tracks the tip of the transaction index. This is used to determine
	// which blocks need to be processed in order to update the index.
	PrefixTransactionIndexTip []byte `prefix_id:"[14]" is_txindex:"true"`
	// <prefix_id, transactionID BlockHash> -> <TransactionMetadata struct>
	PrefixTransactionIDToMetadata []byte `prefix_id:"[15]" is_txindex:"true"`
	// <prefix_id, publicKey []byte, index uint32> -> <txid BlockHash>
	PrefixPublicKeyIndexToTransactionIDs []byte `prefix_id:"[16]" is_txindex:"true"`
	// <prefix_id, publicKey []byte> -> <index uint32>
	PrefixPublicKeyToNextIndex []byte `prefix_id:"[42]" is_txindex:"true"`

	// Main post index.
	// <prefix_id, PostHash BlockHash> -> PostEntry
	PrefixPostHashToPostEntry []byte `prefix_id:"[17]" is_state:"true"`
	// Post sorts
	// <prefix_id, publicKey [33]byte, PostHash> -> <>
	PrefixPosterPublicKeyPostHash []byte `prefix_id:"[18]" is_state:"true"`

	// <prefix_id, tstampNanos uint64, PostHash> -> <>
	PrefixTstampNanosPostHash []byte `prefix_id:"[19]" is_state:"true"`
	// <prefix_id, creatorbps uint64, PostHash> -> <>
	PrefixCreatorBpsPostHash []byte `prefix_id:"[20]" is_state:"true"`
	// <prefix_id, multiplebps uint64, PostHash> -> <>
	PrefixMultipleBpsPostHash []byte `prefix_id:"[21]" is_state:"true"`
	// Comments are just posts that have their ParentStakeID set, and
	// so we have a separate index that allows us to return all the
	// comments for a given StakeID
	// <prefix_id, parent stakeID [33]byte, tstampnanos uint64, post hash> -> <>
	PrefixCommentParentStakeIDToPostHash []byte `prefix_id:"[22]" is_state:"true"`

	// Main profile index
	// <prefix_id, PKID [33]byte> -> ProfileEntry
	PrefixPKIDToProfileEntry []byte `prefix_id:"[23]" is_state:"true"`
	// Profile sorts
	// For username, we set the PKID as a value since the username is not fixed width.
	// We always lowercase usernames when using them as map keys in order to make
	// all uniqueness checks case-insensitive
	// <prefix_id, username> -> <PKID>
	PrefixProfileUsernameToPKID []byte `prefix_id:"[25]" is_state:"true"`
	// This allows us to sort the profiles by the value of their coin (since
	// the amount of DeSo locked in a profile is proportional to coin price).
	PrefixCreatorDeSoLockedNanosCreatorPKID []byte `prefix_id:"[32]" is_state:"true"`
	// The StakeID is a post hash for posts and a public key for users.
	// <prefix_id, StakeIDType, AmountNanos uint64, StakeID [var]byte> -> <>
	PrefixStakeIDTypeAmountStakeIDIndex []byte `prefix_id:"[26]" is_state:"true"`

	// Prefixes for follows:
	// <prefix_id, follower PKID [33]byte, followed PKID [33]byte> -> <>
	// <prefix_id, followed PKID [33]byte, follower PKID [33]byte> -> <>
	PrefixFollowerPKIDToFollowedPKID []byte `prefix_id:"[28]" is_state:"true"`
	PrefixFollowedPKIDToFollowerPKID []byte `prefix_id:"[29]" is_state:"true"`

	// Prefixes for likes:
	// <prefix_id, user pub key [33]byte, liked post hash [32]byte> -> <>
	// <prefix_id, post hash [32]byte, user pub key [33]byte> -> <>
	PrefixLikerPubKeyToLikedPostHash []byte `prefix_id:"[30]" is_state:"true"`
	PrefixLikedPostHashToLikerPubKey []byte `prefix_id:"[31]" is_state:"true"`

	// Prefixes for creator coin fields:
	// <prefix_id, HODLer PKID [33]byte, creator PKID [33]byte> -> <BalanceEntry>
	// <prefix_id, creator PKID [33]byte, HODLer PKID [33]byte> -> <BalanceEntry>
	PrefixHODLerPKIDCreatorPKIDToBalanceEntry []byte `prefix_id:"[33]" is_state:"true"`
	PrefixCreatorPKIDHODLerPKIDToBalanceEntry []byte `prefix_id:"[34]" is_state:"true"`

	PrefixPosterPublicKeyTimestampPostHash []byte `prefix_id:"[35]" is_state:"true"`
	// If no mapping exists for a particular public key, then the PKID is simply
	// the public key itself.
	// <prefix_id, [33]byte> -> <PKID [33]byte>
	PrefixPublicKeyToPKID []byte `prefix_id:"[36]" is_state:"true"`
	// <prefix_id, PKID [33]byte> -> <PublicKey [33]byte>
	PrefixPKIDToPublicKey []byte `prefix_id:"[37]" is_state:"true"`
	// Prefix for storing mempool transactions in badger. These stored transactions are
	// used to restore the state of a node after it is shutdown.
	// <prefix_id, tx hash BlockHash> -> <*MsgDeSoTxn>
	PrefixMempoolTxnHashToMsgDeSoTxn []byte `prefix_id:"[38]"`

	// Prefixes for Reposts:
	// <prefix_id, user pub key [39]byte, reposted post hash [39]byte> -> RepostEntry
	PrefixReposterPubKeyRepostedPostHashToRepostPostHash []byte `prefix_id:"[39]" is_state:"true"`
	// Prefixes for diamonds:
	//  <prefix_id, DiamondReceiverPKID [33]byte, DiamondSenderPKID [33]byte, posthash> -> <DiamondEntry>
	//  <prefix_id, DiamondSenderPKID [33]byte, DiamondReceiverPKID [33]byte, posthash> -> <DiamondEntry>
	PrefixDiamondReceiverPKIDDiamondSenderPKIDPostHash []byte `prefix_id:"[41]" is_state:"true"`
	PrefixDiamondSenderPKIDDiamondReceiverPKIDPostHash []byte `prefix_id:"[43]" is_state:"true"`
	// Public keys that have been restricted from signing blocks.
	// <prefix_id, ForbiddenPublicKey [33]byte> -> <>
	PrefixForbiddenBlockSignaturePubKeys []byte `prefix_id:"[44]" is_state:"true"`

	// These indexes are used in order to fetch the pub keys of users that liked or diamonded a post.
	// 		Reposts: <prefix_id, RepostedPostHash, ReposterPubKey> -> <>
	// 		Quote Reposts: <prefix_id, RepostedPostHash, ReposterPubKey, RepostPostHash> -> <>
	// 		Diamonds: <prefix_id, DiamondedPostHash, DiamonderPubKey [33]byte, DiamondLevel (uint64)> -> <>
	PrefixRepostedPostHashReposterPubKey               []byte `prefix_id:"[45]" is_state:"true"`
	PrefixRepostedPostHashReposterPubKeyRepostPostHash []byte `prefix_id:"[46]" is_state:"true"`
	PrefixDiamondedPostHashDiamonderPKIDDiamondLevel   []byte `prefix_id:"[47]" is_state:"true"`
	// Prefixes for NFT ownership:
	// 	<prefix_id, NFTPostHash [32]byte, SerialNumber uint64> -> NFTEntry
	PrefixPostHashSerialNumberToNFTEntry []byte `prefix_id:"[48]" is_state:"true"`
	//  <prefix_id, PKID [33]byte, IsForSale bool, BidAmountNanos uint64, NFTPostHash[32]byte, SerialNumber uint64> -> NFTEntry
	PrefixPKIDIsForSaleBidAmountNanosPostHashSerialNumberToNFTEntry []byte `prefix_id:"[49]" is_state:"true"`
	// Prefixes for NFT bids:
	//  <prefix_id, NFTPostHash [32]byte, SerialNumber uint64, BidNanos uint64, PKID [33]byte> -> <>
	PrefixPostHashSerialNumberBidNanosBidderPKID []byte `prefix_id:"[50]" is_state:"true"`
	//  <prefix_id, BidderPKID [33]byte, NFTPostHash [32]byte, SerialNumber uint64> -> <BidNanos uint64>
	PrefixBidderPKIDPostHashSerialNumberToBidNanos []byte `prefix_id:"[51]" is_state:"true"`

	// <prefix_id, PublicKey [33]byte> -> uint64
	PrefixPublicKeyToDeSoBalanceNanos []byte `prefix_id:"[52]" is_state:"true"`

	// Block reward prefix:
	//   - This index is needed because block rewards take N blocks to mature, which means we need
	//     a way to deduct them from balance calculations until that point. Without this index, it
	//     would be impossible to figure out which of a user's UTXOs have yet to mature.
	//   - Schema: <prefix_id, hash BlockHash> -> <pubKey [33]byte, uint64 blockRewardNanos>
	PrefixPublicKeyBlockHashToBlockReward []byte `prefix_id:"[53]" is_state:"true"`

	// Prefix for NFT accepted bid entries:
	//   - Note: this index uses a slice to track the history of winning bids for an NFT. It is
	//     not core to consensus and should not be relied upon as it could get inefficient.
	//   - Schema: <prefix_id>, NFTPostHash [32]byte, SerialNumber uint64 -> []NFTBidEntry
	PrefixPostHashSerialNumberToAcceptedBidEntries []byte `prefix_id:"[54]" is_state:"true"`

	// Prefixes for DAO coin fields:
	// <prefix, HODLer PKID [33]byte, creator PKID [33]byte> -> <BalanceEntry>
	// <prefix, creator PKID [33]byte, HODLer PKID [33]byte> -> <BalanceEntry>
	PrefixHODLerPKIDCreatorPKIDToDAOCoinBalanceEntry []byte `prefix_id:"[55]" is_state:"true"`
	PrefixCreatorPKIDHODLerPKIDToDAOCoinBalanceEntry []byte `prefix_id:"[56]" is_state:"true"`

	// Prefix for MessagingGroupEntries indexed by OwnerPublicKey and GroupKeyName:
	//
	// * This index is used to store information about messaging groups. A group is indexed
	//   by the "owner" public key of the user who created the group and the key
	//   name the owner selected when creating the group (can be anything, user-defined).
	//
	// * Groups can have members that all use a shared key to communicate. In this case,
	//   the MessagingGroupEntry will contain the metadata required for each participant to
	//   compute the shared key.
	//
	// * Groups can also consist of a single person, and this is useful for "registering"
	//   a key so that other people can message you. Generally, every user has a mapping of
	//   the form:
	//   - <OwnerPublicKey, "default-key"> -> MessagingGroupEntry
	//   This "singleton" group is used to register a default key so that people can
	//   message this user. Allowing users to register default keys on-chain in this way is required
	//   to make it so that messages can be decrypted on mobile devices, where apps do not have
	//   easy access to the owner key for decrypting messages.
	//
	// <prefix, GroupOwnerPublicKey [33]byte, GroupKeyName [32]byte> -> <MessagingGroupEntry>
	PrefixMessagingGroupEntriesByOwnerPubKeyAndGroupKeyName []byte `prefix_id:"[57]" is_state:"true"`

	// Prefix for Message MessagingGroupMembers:
	//
	// * For each group that a user is a member of, we store a value in this index of
	//   the form:
	//   - <OwnerPublicKey for user, GroupMessagingPublicKey> -> <HackedMessagingGroupEntry>
	//   The value needs to contain enough information to allow us to look up the
	//   group's metatdata in the _PrefixMessagingGroupEntriesByOwnerPubKeyAndGroupKeyName index. It's also convenient for
	//   the value to contain the encrypted messaging key for the user so that we can
	//   decrypt messages for this user *without* looking up the group.
	//
	// * HackedMessagingGroupEntry is a MessagingGroupEntry that we overload to store
	// 	 information on a member of a group. We couldn't use the MessagingGroupMember
	//   because we wanted to store additional information that "back-references" the
	//   MessagingGroupEntry for this group.
	//
	// * Note that GroupMessagingPublicKey != GroupOwnerPublicKey. For this index
	//   it was convenient for various reasons to put the messaging public key into
	//   the index rather than the group owner's public key. This becomes clear if
	//   you read all the fetching code around this index.
	//
	// <prefix, OwnerPublicKey [33]byte, GroupMessagingPublicKey [33]byte> -> <HackedMessagingKeyEntry>
	PrefixMessagingGroupMetadataByMemberPubKeyAndGroupMessagingPubKey []byte `prefix_id:"[58]" is_state:"true"`

	// Prefix for Authorize Derived Key transactions:
	// 		<prefix_id, OwnerPublicKey [33]byte, DerivedPublicKey [33]byte> -> <DerivedKeyEntry>
	PrefixAuthorizeDerivedKey []byte `prefix_id:"[59]" is_state:"true"`

	// Prefixes for DAO coin limit orders
	// This index powers the order book.
	// <
	//   _PrefixDAOCoinLimitOrder
	//   BuyingDAOCoinCreatorPKID [33]byte
	//   SellingDAOCoinCreatorPKID [33]byte
	//   ScaledExchangeRateCoinsToSellPerCoinToBuy [32]byte
	//   BlockHeight [32]byte
	//   OrderID [32]byte
	// > -> <DAOCoinLimitOrderEntry>
	//
	// This index allows users to query for their open orders.
	// <
	//   _PrefixDAOCoinLimitOrderByTransactorPKID
	//   TransactorPKID [33]byte
	//   BuyingDAOCoinCreatorPKID [33]byte
	//   SellingDAOCoinCreatorPKID [33]byte
	//   OrderID [32]byte
	// > -> <DAOCoinLimitOrderEntry>
	//
	// This index allows users to query for a single order by ID.
	// This is useful in e.g. cancelling an order.
	// <
	//   _PrefixDAOCoinLimitOrderByOrderID
	//   OrderID [32]byte
	// > -> <DAOCoinLimitOrderEntry>
	PrefixDAOCoinLimitOrder                 []byte `prefix_id:"[60]" is_state:"true"`
	PrefixDAOCoinLimitOrderByTransactorPKID []byte `prefix_id:"[61]" is_state:"true"`
	PrefixDAOCoinLimitOrderByOrderID        []byte `prefix_id:"[62]" is_state:"true"`
	// NEXT_TAG: 63
}

// StatePrefixToDeSoEncoder maps each state prefix to a DeSoEncoder type that is stored under that prefix.
// In particular, this is used by the EncoderMigration service, and used to determine how to encode/decode db entries.
func StatePrefixToDeSoEncoder(prefix []byte) (_isEncoder bool, _encoder DeSoEncoder) {
	if len(prefix) > MaxPrefixLen {
		panic(any(fmt.Sprintf("Called with prefix longer than MaxPrefixLen, prefix: (%v), MaxPrefixLen: (%v)", prefix, MaxPrefixLen)))
	}
	if bytes.Equal(prefix, Prefixes.PrefixUtxoKeyToUtxoEntry) {
		// prefix_id:"[5]"
		return true, &UtxoEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPubKeyUtxoKey) {
		// prefix_id:"[7]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixUtxoNumEntries) {
		// prefix_id:"[8]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixNanosPurchased) {
		// prefix_id:"[10]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixUSDCentsPerBitcoinExchangeRate) {
		// prefix_id:"[27]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixGlobalParams) {
		// prefix_id:"[40]"
		return true, &GlobalParamsEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixBitcoinBurnTxIDs) {
		// prefix_id:"[11]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixPublicKeyTimestampToPrivateMessage) {
		// prefix_id:"[12]"
		return true, &MessageEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPostHashToPostEntry) {
		// prefix_id:"[17]"
		return true, &PostEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPosterPublicKeyPostHash) {
		// prefix_id:"[18]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixTstampNanosPostHash) {
		// prefix_id:"[19]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixCreatorBpsPostHash) {
		// prefix_id:"[20]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixMultipleBpsPostHash) {
		// prefix_id:"[21]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixCommentParentStakeIDToPostHash) {
		// prefix_id:"[22]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixPKIDToProfileEntry) {
		// prefix_id:"[23]"
		return true, &ProfileEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixProfileUsernameToPKID) {
		// prefix_id:"[25]"
		// This prefix just encodes PKIDs, but it's not using the DeSoEncoder interface so for the sake of simplicity we just skip it.
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID) {
		// prefix_id:"[32]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixStakeIDTypeAmountStakeIDIndex) {
		// prefix_id:"[26]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixFollowerPKIDToFollowedPKID) {
		// prefix_id:"[28]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixFollowedPKIDToFollowerPKID) {
		// prefix_id:"[29]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixLikerPubKeyToLikedPostHash) {
		// prefix_id:"[30]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixLikedPostHashToLikerPubKey) {
		// prefix_id:"[31]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixHODLerPKIDCreatorPKIDToBalanceEntry) {
		// prefix_id:"[33]"
		return true, &BalanceEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixCreatorPKIDHODLerPKIDToBalanceEntry) {
		// prefix_id:"[34]"
		return true, &BalanceEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPosterPublicKeyTimestampPostHash) {
		// prefix_id:"[35]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixPublicKeyToPKID) {
		// prefix_id:"[36]"
		return true, &PKIDEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPKIDToPublicKey) {
		// prefix_id:"[37]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixReposterPubKeyRepostedPostHashToRepostPostHash) {
		// prefix_id:"[39]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixDiamondReceiverPKIDDiamondSenderPKIDPostHash) {
		// prefix_id:"[41]"
		return true, &DiamondEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixDiamondSenderPKIDDiamondReceiverPKIDPostHash) {
		// prefix_id:"[43]"
		return true, &DiamondEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixForbiddenBlockSignaturePubKeys) {
		// prefix_id:"[44]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixRepostedPostHashReposterPubKey) {
		// prefix_id:"[45]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixRepostedPostHashReposterPubKeyRepostPostHash) {
		// prefix_id:"[46]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixDiamondedPostHashDiamonderPKIDDiamondLevel) {
		// prefix_id:"[47]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixPostHashSerialNumberToNFTEntry) {
		// prefix_id:"[48]"
		return true, &NFTEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPKIDIsForSaleBidAmountNanosPostHashSerialNumberToNFTEntry) {
		// prefix_id:"[49]"
		return true, &NFTEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPostHashSerialNumberBidNanosBidderPKID) {
		// prefix_id:"[50]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixBidderPKIDPostHashSerialNumberToBidNanos) {
		// prefix_id:"[51]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixPostHashSerialNumberToAcceptedBidEntries) {
		// prefix_id:"[54]"
		return true, &NFTBidEntryBundle{}
	} else if bytes.Equal(prefix, Prefixes.PrefixPublicKeyToDeSoBalanceNanos) {
		// prefix_id:"[52]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixPublicKeyBlockHashToBlockReward) {
		// prefix_id:"[53]"
		return false, nil
	} else if bytes.Equal(prefix, Prefixes.PrefixHODLerPKIDCreatorPKIDToDAOCoinBalanceEntry) {
		// prefix_id:"[55]"
		return true, &BalanceEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixCreatorPKIDHODLerPKIDToDAOCoinBalanceEntry) {
		// prefix_id:"[56]"
		return true, &BalanceEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixMessagingGroupEntriesByOwnerPubKeyAndGroupKeyName) {
		// prefix_id:"[57]"
		return true, &MessagingGroupEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixMessagingGroupMetadataByMemberPubKeyAndGroupMessagingPubKey) {
		// prefix_id:"[58]"
		return true, &MessagingGroupEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixAuthorizeDerivedKey) {
		// prefix_id:"[59]"
		return true, &DerivedKeyEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixDAOCoinLimitOrder) {
		// prefix_id:"[60]"
		return true, &DAOCoinLimitOrderEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixDAOCoinLimitOrderByTransactorPKID) {
		// prefix_id:"[61]"
		return true, &DAOCoinLimitOrderEntry{}
	} else if bytes.Equal(prefix, Prefixes.PrefixDAOCoinLimitOrderByOrderID) {
		// prefix_id:"[62]"
		return true, &DAOCoinLimitOrderEntry{}
	}

	return true, nil
}

func StateKeyToDeSoEncoder(key []byte) (_isEncoder bool, _encoder DeSoEncoder) {
	if MaxPrefixLen > 1 {
		panic(any(fmt.Errorf("this function only works if MaxPrefixLen is 1 but currently MaxPrefixLen=(%v)", MaxPrefixLen)))
	}
	return StatePrefixToDeSoEncoder(key[:1])
}

// getPrefixIdValue parses the DBPrefixes struct tags to fetch the prefix_id values.
func getPrefixIdValue(structFields reflect.StructField, fieldType reflect.Type) (prefixId reflect.Value) {
	var ref reflect.Value
	// Get the prefix_id tag and parse it as byte array.
	if value := structFields.Tag.Get("prefix_id"); value != "-" {
		ref = reflect.New(fieldType)
		ref.Elem().Set(reflect.MakeSlice(fieldType, 0, 0))
		if value != "" && value != "[]" {
			if err := json.Unmarshal([]byte(value), ref.Interface()); err != nil {
				panic(any(err))
			}
		}
	} else {
		panic(any(fmt.Errorf("prefix_id cannot be empty")))
	}
	return ref.Elem()
}

// GetPrefixes loads all prefix_id byte array values into a DBPrefixes struct, and returns it.
func GetPrefixes() *DBPrefixes {
	prefixes := &DBPrefixes{}

	// Iterate over all DBPrefixes fields and parse their prefix_id tags.
	prefixElements := reflect.ValueOf(prefixes).Elem()
	structFields := prefixElements.Type()
	for i := 0; i < structFields.NumField(); i++ {
		prefixField := prefixElements.Field(i)
		prefixId := getPrefixIdValue(structFields.Field(i), prefixField.Type())
		prefixField.Set(prefixId)
	}
	return prefixes
}

// DBStatePrefixes is a helper struct that stores information about state-related prefixes.
type DBStatePrefixes struct {
	Prefixes *DBPrefixes

	// StatePrefixesMap maps prefixes to whether they are state (true) or non-state (false) prefixes.
	StatePrefixesMap map[byte]bool

	// StatePrefixesList is a list of state prefixes.
	StatePrefixesList [][]byte

	// TxIndexPrefixes is a list of TxIndex prefixes
	TxIndexPrefixes [][]byte
}

// GetStatePrefixes() creates a DBStatePrefixes object from the DBPrefixes struct and returns it. We
// parse the prefix_id and is_state tags.
func GetStatePrefixes() *DBStatePrefixes {
	// Initialize the DBStatePrefixes struct.
	statePrefixes := &DBStatePrefixes{}
	statePrefixes.Prefixes = &DBPrefixes{}
	statePrefixes.StatePrefixesMap = make(map[byte]bool)

	// Iterate over all the DBPrefixes fields and parse the prefix_id and is_state tags.
	prefixElements := reflect.ValueOf(statePrefixes.Prefixes).Elem()
	structFields := prefixElements.Type()
	for i := 0; i < structFields.NumField(); i++ {
		prefixField := prefixElements.Field(i)
		prefixId := getPrefixIdValue(structFields.Field(i), prefixField.Type())
		prefixBytes := prefixId.Bytes()
		if len(prefixBytes) > MaxPrefixLen {
			panic(any(fmt.Errorf("prefix (%v) is longer than MaxPrefixLen: (%v)",
				structFields.Field(i).Name, MaxPrefixLen)))
		}
		prefix := prefixBytes[0]
		if statePrefixes.StatePrefixesMap[prefix] {
			panic(any(fmt.Errorf("prefix (%v) already exists in StatePrefixesMap. You created a "+
				"prefix overlap, fix it", structFields.Field(i).Name)))
		}
		if structFields.Field(i).Tag.Get("is_state") == "true" {
			statePrefixes.StatePrefixesMap[prefix] = true
			statePrefixes.StatePrefixesList = append(statePrefixes.StatePrefixesList, []byte{prefix})
		} else if structFields.Field(i).Tag.Get("is_txindex") == "true" {
			statePrefixes.TxIndexPrefixes = append(statePrefixes.TxIndexPrefixes, []byte{prefix})
			statePrefixes.StatePrefixesMap[prefix] = false
		} else {
			statePrefixes.StatePrefixesMap[prefix] = false
		}
	}
	// Sort prefixes.
	sort.Slice(statePrefixes.StatePrefixesList, func(i int, j int) bool {
		switch bytes.Compare(statePrefixes.StatePrefixesList[i], statePrefixes.StatePrefixesList[j]) {
		case 0:
			return true
		case -1:
			return true
		case 1:
			return false
		}
		return false
	})
	return statePrefixes
}

// isStateKey checks if a key is a state-related key.
func isStateKey(key []byte) bool {
	if MaxPrefixLen > 1 {
		panic(any(fmt.Errorf("this function only works if MaxPrefixLen is 1 but currently MaxPrefixLen=(%v)", MaxPrefixLen)))
	}
	prefix := key[0]
	isState, exists := StatePrefixes.StatePrefixesMap[prefix]
	return exists && isState
}

// isTxIndexKey checks if a key is a txindex-related key.
func isTxIndexKey(key []byte) bool {
	if MaxPrefixLen > 1 {
		panic(any(fmt.Errorf("this function only works if MaxPrefixLen is 1 but currently MaxPrefixLen=(%v)", MaxPrefixLen)))
	}
	prefix := key[0]
	for _, txIndexPrefix := range StatePrefixes.TxIndexPrefixes {
		if prefix == txIndexPrefix[0] {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------------------
// DB Operations
// -------------------------------------------------------------------------------------

// EncodeKeyValue encodes DB key and value similarly to how DER signatures are encoded. The format is:
// len(key + value) || len(key) || key || len(value) || value
// This encoding is unique meaning (key, value) and (key', value') pairs have the same encoding if and
// only if key = key' and value = value'
func EncodeKeyValue(key []byte, value []byte) []byte {
	data := []byte{}

	data = append(data, EncodeUint64(uint64(len(key)+len(value)))...)
	data = append(data, EncodeUint64(uint64(len(key)))...)
	data = append(data, key...)
	data = append(data, EncodeUint64(uint64(len(value)))...)
	data = append(data, value...)

	return data
}

func EncodeKeyAndValueForChecksum(key []byte, value []byte, blockHeight uint64) []byte {
	checksumValue := value
	if isEncoder, encoder := StateKeyToDeSoEncoder(key); isEncoder && encoder != nil {
		rr := bytes.NewReader(value)
		if exists, err := DecodeFromBytes(encoder, rr); exists && err == nil {
			// We skip metadata in checksum computation.
			checksumValue = EncodeToBytes(blockHeight, encoder, true)
		} else if err != nil {
			glog.Errorf("Some odd problem: isEncoder %v encoder %v, key bytes (%v), value bytes (%v), blockHeight (%v)",
				isEncoder, encoder, key, checksumValue, blockHeight)
			panic(any(errors.Wrapf(err, "EncodeKeyAndValueForChecksum: The schema is corrupted or value doesn't match the key")))
		}
	}

	return EncodeKeyValue(key, checksumValue)
}

// DBSetWithTxn is a wrapper around BadgerDB Set function which allows us to add computation
// prior to DB writes. In particular, we use it to maintain a dynamic LRU cache, compute the
// state checksum, and to build DB snapshots with ancestral records.
func DBSetWithTxn(txn *badger.Txn, snap *Snapshot, key []byte, value []byte) error {
	// We only cache / update ancestral records when we're dealing with state prefix.
	isState := snap != nil && snap.isState(key)
	var ancestralValue []byte
	var getError error

	// If snapshot was provided, we will need to load the current value of the record
	// so that we can later write it in the ancestral record. We first lookup cache.
	if isState {
		// We check if we've already read this key and stored it in the cache.
		// Otherwise, we fetch the current value of this record from the DB.
		ancestralValue, getError = DBGetWithTxn(txn, snap, key)

		// If there is some error with the DB read, other than non-existent key, we return.
		if getError != nil && getError != badger.ErrKeyNotFound {
			return errors.Wrapf(getError, "DBSetWithTxn: problem reading record "+
				"from DB with key: %v", key)
		}
	}

	// We update the DB record with the intended value.
	err := txn.Set(key, value)
	if err != nil {
		return errors.Wrapf(err, "DBSetWithTxn: Problem setting record "+
			"in DB with key: %v, value: %v", key, value)
	}

	// After a successful DB write, we update the snapshot.
	if isState {
		keyString := hex.EncodeToString(key)

		// Update ancestral record structures depending on the existing DB record.
		if err := snap.PrepareAncestralRecord(keyString, ancestralValue, getError != badger.ErrKeyNotFound); err != nil {
			return errors.Wrapf(err, "DBSetWithTxn: Problem preparing ancestral record")
		}
		// Now save the newest record to cache.
		snap.DatabaseCache.Add(keyString, value)

		if !snap.disableChecksum {
			// We have to remove the previous value from the state checksum.
			// Because checksum is commutative, we can safely remove the past value here.
			if getError == nil {
				snap.RemoveChecksumBytes(key, ancestralValue)
			}
			// We also add the new record to the checksum.
			snap.AddChecksumBytes(key, value)
		}
	}
	return nil
}

// DBGetWithTxn is a wrapper function around the BadgerDB get function. It returns
// the DB entry associated with the given key and handles the logic around the LRU cache.
// Whenever we read/write records in the DB, we place a copy in the LRU cache to save
// us lookup time.
func DBGetWithTxn(txn *badger.Txn, snap *Snapshot, key []byte) ([]byte, error) {
	// We only cache / update ancestral records when we're dealing with state prefix.
	isState := snap != nil && snap.isState(key)
	keyString := hex.EncodeToString(key)

	// Lookup the snapshot cache and check if we've already stored a value there.
	if isState {
		if val, exists := snap.DatabaseCache.Lookup(keyString); exists {
			return val.([]byte), nil
		}
	}

	// If record doesn't exist in cache, we get it from the DB.
	item, err := txn.Get(key)
	if err != nil {
		return nil, err
	}
	itemData, err := item.ValueCopy(nil)
	if err != nil {
		return nil, err
	}

	// If a flush takes place, we don't update cache. It will be updated in DBSetWithTxn.
	if isState {
		// Hold the snapshot memory lock just to be e
		snap.Status.MemoryLock.Lock()
		defer snap.Status.MemoryLock.Unlock()
		if !snap.Status.IsFlushingWithoutLock() {
			snap.DatabaseCache.Add(keyString, itemData)
		}
	}
	return itemData, nil
}

// DBDeleteWithTxn is a wrapper function around BadgerDB delete function.
// It allows us to update the snapshot LRU cache, checksum, and ancestral records.
func DBDeleteWithTxn(txn *badger.Txn, snap *Snapshot, key []byte) error {
	var ancestralValue []byte
	var getError error
	isState := snap != nil && snap.isState(key)

	// If snapshot was provided, we will need to load the current value of the record
	// so that we can later write it in the ancestral record. We first lookup cache.
	if isState {
		// We check if we've already read this key and stored it in the cache.
		// Otherwise, we fetch the current value of this record from the DB.
		ancestralValue, getError = DBGetWithTxn(txn, snap, key)
		// If the key doesn't exist then there is no point in deleting this entry.
		if getError == badger.ErrKeyNotFound {
			return nil
		}

		// If there is some error with the DB read, other than non-existent key, we return.
		if getError != nil {
			return errors.Wrapf(getError, "DBDeleteWithTxn: problem checking for DB record "+
				"with key: %v", key)
		}
	}

	err := txn.Delete(key)
	if err != nil {
		return errors.Wrapf(err, "DBDeleteWithTxn: Problem deleting record "+
			"from DB with key: %v", key)
	}

	// After a successful DB delete, we update the snapshot.
	if isState {
		keyString := hex.EncodeToString(key)

		// Update ancestral record structures depending on the existing DB record.
		if err := snap.PrepareAncestralRecord(keyString, ancestralValue, true); err != nil {
			return errors.Wrapf(err, "DBDeleteWithTxn: Problem preparing ancestral record")
		}
		// Now delete the past record from the cache.
		snap.DatabaseCache.Delete(keyString)
		// We have to remove the previous value from the state checksum.
		// Because checksum is commutative, we can safely remove the past value here.
		if !snap.disableChecksum {
			snap.RemoveChecksumBytes(key, ancestralValue)
		}
	}
	return nil
}

// DBIteratePrefixKeys fetches a chunk of records from the provided db at a provided prefix,
// and beginning with the provided startKey. The chunk will have a total size of at least targetBytes.
// If the startKey is a valid key in the db, it will be the first entry in the returned dbEntries.
// If we have exhausted all entries for a prefix then _isChunkFull will be set as false, and true otherwise,
// when there are more entries in the db at the prefix.
func DBIteratePrefixKeys(db *badger.DB, prefix []byte, startKey []byte, targetBytes uint32) (
	_dbEntries []*DBEntry, _isChunkFull bool, _err error) {
	var dbEntries []*DBEntry
	var totalBytes int
	var isChunkFull bool

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		// Iterate over the prefix as long as there are valid keys in the DB.
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(startKey); it.ValidForPrefix(prefix) && !isChunkFull; it.Next() {
			item := it.Item()
			key := item.Key()
			// Add the key, value pair to our dbEntries list.
			err := item.Value(func(value []byte) error {
				dbEntries = append(dbEntries, KeyValueToDBEntry(key, value))
				// If total amount of bytes in the dbEntries exceeds the target bytes size, we set the chunk as full.
				totalBytes += len(key) + len(value)
				if totalBytes > int(targetBytes) && len(dbEntries) > 1 {
					isChunkFull = true
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		// Return false for _isChunkFull to indicate that we shouldn't query this prefix again because
		// something is wrong.
		return nil, false, err
	}
	return dbEntries, isChunkFull, nil
}

// DBDeleteAllStateRecords is an auxiliary function that is used to clean up the state
// before starting hyper sync. _shouldErase = true is returned when it is faster to use
// os.RemoveAll(dbDir) instead of deleting records manually.
func DBDeleteAllStateRecords(db *badger.DB) (_shouldErase bool, _error error) {
	maxKeys := 10000
	shouldErase := false

	go func() {
		time.Sleep(1 * time.Minute)
		shouldErase = true
	}()

	// Iterate over all state prefixes.
	for _, prefix := range StatePrefixes.StatePrefixesList {
		startKey := prefix
		fetchingPrefix := true

		// We will delete all records for a prefix step by step. We do this in chunks of 10,000 keys,
		// to make sure we don't overload badger DB with the size of our queries. Whenever a
		// chunk is not full, that is isChunkFull = false, it means that we've exhausted all
		// entries for a prefix.
		for fetchingPrefix {
			if shouldErase {
				return true, nil
			}
			var isChunkFull bool
			var keys [][]byte
			err := db.View(func(txn *badger.Txn) error {
				totalKeys := 0
				opts := badger.DefaultIteratorOptions
				opts.AllVersions = false
				opts.PrefetchValues = false
				// Iterate over the prefix as long as there are valid keys in the DB.
				it := txn.NewIterator(opts)
				defer it.Close()
				for it.Seek(startKey); it.ValidForPrefix(prefix) && !isChunkFull; it.Next() {
					key := it.Item().KeyCopy(nil)
					keys = append(keys, key)
					totalKeys += 1
					if totalKeys > maxKeys {
						isChunkFull = true
					}
				}
				return nil
			})
			if err != nil {
				return true, errors.Wrapf(err, "DBDeleteAllStateRecords: problem fetching entries from the db at "+
					"prefix (%v)", prefix)
			}
			fetchingPrefix = isChunkFull
			glog.V(1).Infof("DeleteAllStateRecords: Deleting prefix: (%v) with total of (%v) "+
				"entries", prefix, len(keys))
			// Now delete all these keys.
			err = db.Update(func(txn *badger.Txn) error {
				for _, key := range keys {
					err := txn.Delete(key)
					if err != nil {
						return errors.Wrapf(err, "DeleteAllStateRecords: Problem deleting key (%v)", key)
					}
				}
				return nil
			})
			if err != nil {
				return true, err
			}
		}
	}
	return false, nil
}

// -------------------------------------------------------------------------------------
// DB Controllers
// -------------------------------------------------------------------------------------

func DBGetPKIDEntryForPublicKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte) *PKIDEntry {
	if len(publicKey) == 0 {
		return nil
	}

	prefix := append([]byte{}, Prefixes.PrefixPublicKeyToPKID...)
	pkidBytes, err := DBGetWithTxn(txn, snap, append(prefix, publicKey...))

	if err != nil {
		// If we don't have a mapping from public key to PKID in the db,
		// then we use the public key itself as the PKID. Doing this makes
		// it so that the PKID is generally the *first* public key that the
		// user ever associated with a particular piece of data.
		return &PKIDEntry{
			PKID:      PublicKeyToPKID(publicKey),
			PublicKey: publicKey,
		}
	}

	// If we get here then it means we actually had a PKID in the DB.
	// So return that pkid.
	pkidEntryObj := &PKIDEntry{}
	rr := bytes.NewReader(pkidBytes)
	DecodeFromBytes(pkidEntryObj, rr)
	return pkidEntryObj
}

func DBGetPKIDEntryForPublicKey(db *badger.DB, snap *Snapshot, publicKey []byte) *PKIDEntry {
	var pkid *PKIDEntry
	db.View(func(txn *badger.Txn) error {
		pkid = DBGetPKIDEntryForPublicKeyWithTxn(txn, snap, publicKey)
		return nil
	})
	return pkid
}

func DBGetPublicKeyForPKIDWithTxn(txn *badger.Txn, snap *Snapshot, pkidd *PKID) []byte {
	prefix := append([]byte{}, Prefixes.PrefixPKIDToPublicKey...)
	pkidBytes, err := DBGetWithTxn(txn, snap, append(prefix, pkidd[:]...))

	if err != nil {
		// If we don't have a mapping in the db then return the pkid itself
		// as the public key.
		pkid := pkidd.NewPKID()
		return pkid[:]
	}

	// If we get here then it means we actually had a public key mapping in the DB.
	// So return that public key.

	return pkidBytes
}

func DBGetPublicKeyForPKID(db *badger.DB, snap *Snapshot, pkidd *PKID) []byte {
	var publicKey []byte
	db.View(func(txn *badger.Txn) error {
		publicKey = DBGetPublicKeyForPKIDWithTxn(txn, snap, pkidd)
		return nil
	})
	return publicKey
}

func DBPutPKIDMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	publicKey []byte, pkidEntry *PKIDEntry, params *DeSoParams) error {

	// If the PKID entry is identical to the public key, there's no point in saving it in the DB.
	// All functions fetching PKID will already return the public key if PKID was unset.
	if reflect.DeepEqual(publicKey, pkidEntry.PKID.ToBytes()) {
		return nil
	}

	// Set the main pub key -> pkid mapping.
	{
		prefix := append([]byte{}, Prefixes.PrefixPublicKeyToPKID...)
		pubKeyToPkidKey := append(prefix, publicKey...)
		if err := DBSetWithTxn(txn, snap, pubKeyToPkidKey, EncodeToBytes(blockHeight, pkidEntry)); err != nil {

			return errors.Wrapf(err, "DBPutPKIDMappingsWithTxn: Problem "+
				"adding mapping for pkid: %v public key: %v",
				PkToString(pkidEntry.PKID[:], params), PkToString(publicKey, params))
		}
	}

	// Set the reverse mapping: pkid -> pub key
	{
		prefix := append([]byte{}, Prefixes.PrefixPKIDToPublicKey...)
		pkidToPubKey := append(prefix, pkidEntry.PKID[:]...)
		if err := DBSetWithTxn(txn, snap, pkidToPubKey, publicKey); err != nil {

			return errors.Wrapf(err, "DBPutPKIDMappingsWithTxn: Problem "+
				"adding mapping for pkid: %v public key: %v",
				PkToString(pkidEntry.PKID[:], params), PkToString(publicKey, params))
		}
	}

	return nil
}

func DBDeletePKIDMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, params *DeSoParams) error {

	// Look up the pkid for the public key.
	pkidEntry := DBGetPKIDEntryForPublicKeyWithTxn(txn, snap, publicKey)

	{
		prefix := append([]byte{}, Prefixes.PrefixPublicKeyToPKID...)
		pubKeyToPkidKey := append(prefix, publicKey...)
		if err := DBDeleteWithTxn(txn, snap, pubKeyToPkidKey); err != nil {

			return errors.Wrapf(err, "DBDeletePKIDMappingsWithTxn: Problem "+
				"deleting mapping for public key: %v",
				PkToString(publicKey, params))
		}
	}

	{
		prefix := append([]byte{}, Prefixes.PrefixPKIDToPublicKey...)
		pubKeyToPkidKey := append(prefix, pkidEntry.PKID[:]...)
		if err := DBDeleteWithTxn(txn, snap, pubKeyToPkidKey); err != nil {

			return errors.Wrapf(err, "DBDeletePKIDMappingsWithTxn: Problem "+
				"deleting mapping for pkid: %v",
				PkToString(pkidEntry.PKID[:], params))
		}
	}

	return nil
}

func EnumerateKeysForPrefix(db *badger.DB, dbPrefix []byte) (_keysFound [][]byte, _valsFound [][]byte) {
	return _enumerateKeysForPrefix(db, dbPrefix)
}

// A helper function to enumerate all of the values for a particular prefix.
func _enumerateKeysForPrefix(db *badger.DB, dbPrefix []byte) (_keysFound [][]byte, _valsFound [][]byte) {
	keysFound := [][]byte{}
	valsFound := [][]byte{}

	dbErr := db.View(func(txn *badger.Txn) error {
		var err error
		keysFound, valsFound, err = _enumerateKeysForPrefixWithTxn(txn, dbPrefix)
		if err != nil {
			return err
		}
		return nil
	})
	if dbErr != nil {
		glog.Errorf("_enumerateKeysForPrefix: Problem fetching keys and values from db: %v", dbErr)
		return nil, nil
	}

	return keysFound, valsFound
}

func _enumerateKeysForPrefixWithTxn(txn *badger.Txn, dbPrefix []byte) (_keysFound [][]byte, _valsFound [][]byte, _err error) {
	keysFound := [][]byte{}
	valsFound := [][]byte{}

	opts := badger.DefaultIteratorOptions
	nodeIterator := txn.NewIterator(opts)
	defer nodeIterator.Close()
	prefix := dbPrefix
	for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
		key := nodeIterator.Item().Key()
		keyCopy := make([]byte, len(key))
		copy(keyCopy[:], key[:])

		valCopy, err := nodeIterator.Item().ValueCopy(nil)
		if err != nil {
			return nil, nil, err
		}
		keysFound = append(keysFound, keyCopy)
		valsFound = append(valsFound, valCopy)
	}
	return keysFound, valsFound, nil
}

// A helper function to enumerate a limited number of the values for a particular prefix.
func _enumerateLimitedKeysReversedForPrefix(db *badger.DB, dbPrefix []byte, limit uint64) (_keysFound [][]byte, _valsFound [][]byte) {
	keysFound := [][]byte{}
	valsFound := [][]byte{}

	dbErr := db.View(func(txn *badger.Txn) error {
		var err error
		keysFound, valsFound, err = _enumerateLimitedKeysReversedForPrefixWithTxn(txn, dbPrefix, limit)
		return err
	})
	if dbErr != nil {
		glog.Errorf("_enumerateKeysForPrefix: Problem fetching keys and values from db: %v", dbErr)
		return nil, nil
	}

	return keysFound, valsFound
}

func _enumerateLimitedKeysReversedForPrefixWithTxn(txn *badger.Txn, dbPrefix []byte, limit uint64) (_keysFound [][]byte, _valsFound [][]byte, _err error) {
	keysFound := [][]byte{}
	valsFound := [][]byte{}

	opts := badger.DefaultIteratorOptions

	// Go in reverse order
	opts.Reverse = true

	nodeIterator := txn.NewIterator(opts)
	defer nodeIterator.Close()
	prefix := dbPrefix

	counter := uint64(0)
	for nodeIterator.Seek(append(prefix, 0xff)); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
		if counter == limit {
			break
		}
		counter++

		key := nodeIterator.Item().Key()
		keyCopy := make([]byte, len(key))
		copy(keyCopy[:], key[:])

		valCopy, err := nodeIterator.Item().ValueCopy(nil)
		if err != nil {
			return nil, nil, err
		}
		keysFound = append(keysFound, keyCopy)
		valsFound = append(valsFound, valCopy)
	}
	return keysFound, valsFound, nil
}

// -------------------------------------------------------------------------------------
// DeSo balance mapping functions
// -------------------------------------------------------------------------------------

func _dbKeyForPublicKeyToDeSoBalanceNanos(publicKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPublicKeyToDeSoBalanceNanos...)
	key := append(prefixCopy, publicKey...)
	return key
}

func DbGetPrefixForPublicKeyToDesoBalanceNanos() []byte {
	return append([]byte{}, Prefixes.PrefixPublicKeyToDeSoBalanceNanos...)
}

func DbGetDeSoBalanceNanosForPublicKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte,
) (_balance uint64, _err error) {

	key := _dbKeyForPublicKeyToDeSoBalanceNanos(publicKey)

	desoBalanceBytes, err := DBGetWithTxn(txn, snap, key)
	// If balance hasn't been set before, then we would error with key not found.
	if err == badger.ErrKeyNotFound {
		return uint64(0), nil
	}
	if err != nil {
		return uint64(0), errors.Wrapf(
			err, "DbGetDeSoBalanceNanosForPublicKeyWithTxn: Problem getting balance for: %s ",
			PkToStringBoth(publicKey))
	}

	desoBalance := DecodeUint64(desoBalanceBytes)

	return desoBalance, nil
}

func DbGetDeSoBalanceNanosForPublicKey(db *badger.DB, snap *Snapshot, publicKey []byte,
) (_balance uint64, _err error) {
	ret := uint64(0)
	dbErr := db.View(func(txn *badger.Txn) error {
		var err error
		ret, err = DbGetDeSoBalanceNanosForPublicKeyWithTxn(txn, snap, publicKey)
		if err != nil {
			return fmt.Errorf("DbGetDeSoBalanceNanosForPublicKey: %v", err)
		}
		return nil
	})
	if dbErr != nil {
		return ret, dbErr
	}
	return ret, nil
}

func DbPutDeSoBalanceForPublicKeyWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, balanceNanos uint64) error {

	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutDeSoBalanceForPublicKeyWithTxn: Public key "+
			"length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}

	balanceBytes := EncodeUint64(balanceNanos)

	if err := DBSetWithTxn(txn, snap, _dbKeyForPublicKeyToDeSoBalanceNanos(publicKey), balanceBytes); err != nil {

		return errors.Wrapf(
			err, "DbPutDeSoBalanceForPublicKey: Problem adding balance mapping of %d for: %s ",
			balanceNanos, PkToStringBoth(publicKey))
	}

	return nil
}

func DbPutDeSoBalanceForPublicKey(handle *badger.DB, snap *Snapshot,
	publicKey []byte, balanceNanos uint64) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutDeSoBalanceForPublicKeyWithTxn(txn, snap, publicKey, balanceNanos)
	})
}

func DbDeletePublicKeyToDeSoBalanceWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte) error {

	if err := DBDeleteWithTxn(txn, snap, _dbKeyForPublicKeyToDeSoBalanceNanos(publicKey)); err != nil {
		return errors.Wrapf(err, "DbDeletePublicKeyToDeSoBalanceWithTxn: Problem deleting "+
			"balance for public key %s", PkToStringMainnet(publicKey))
	}

	return nil
}

func DbDeletePublicKeyToDeSoBalance(handle *badger.DB, snap *Snapshot, publicKey []byte) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbDeletePublicKeyToDeSoBalanceWithTxn(txn, snap, publicKey)
	})
}

// -------------------------------------------------------------------------------------
// PrivateMessage mapping functions
// <public key (33 bytes) || uint64 big-endian> -> <MessageEntry>
// -------------------------------------------------------------------------------------

func _dbKeyForMessageEntry(publicKey []byte, tstampNanos uint64) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPublicKeyTimestampToPrivateMessage...)
	key := append(prefixCopy, publicKey...)
	key = append(key, EncodeUint64(tstampNanos)...)
	return key
}

func _dbSeekPrefixForMessagePublicKey(publicKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPublicKeyTimestampToPrivateMessage...)
	return append(prefixCopy, publicKey...)
}

// Note that this adds a mapping for the sender *and* the recipient.
func DBPutMessageEntryWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	messageKey MessageKey, messageEntry *MessageEntry) error {

	if err := IsByteArrayValidPublicKey(messageEntry.SenderPublicKey[:]); err != nil {
		return errors.Wrapf(err, "DBPutMessageEntryWithTxn: Problem validating sender public key")
	}
	if err := IsByteArrayValidPublicKey(messageEntry.RecipientPublicKey[:]); err != nil {
		return errors.Wrapf(err, "DBPutMessageEntryWithTxn: Problem validating recipient public key")
	}
	if err := ValidateGroupPublicKeyAndName(messageEntry.SenderMessagingPublicKey[:], messageEntry.SenderMessagingGroupKeyName[:]); err != nil {
		return errors.Wrapf(err, "DBPutMessageEntryWithTxn: Problem validating sender public key and key name")
	}
	if err := ValidateGroupPublicKeyAndName(messageEntry.RecipientMessagingPublicKey[:], messageEntry.RecipientMessagingGroupKeyName[:]); err != nil {
		return errors.Wrapf(err, "DBPutMessageEntryWithTxn: Problem validating recipient public key and key name")
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForMessageEntry(
		messageKey.PublicKey[:], messageKey.TstampNanos), EncodeToBytes(blockHeight, messageEntry)); err != nil {

		return errors.Wrapf(err, "DBPutMessageEntryWithTxn: Problem setting the message (%v)", EncodeToBytes(blockHeight, messageEntry))
	}

	return nil
}

func DBPutMessageEntry(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	messageKey MessageKey, messageEntry *MessageEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutMessageEntryWithTxn(txn, snap, blockHeight, messageKey, messageEntry)
	})
}

func DBGetMessageEntryWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, tstampNanos uint64) *MessageEntry {

	key := _dbKeyForMessageEntry(publicKey, tstampNanos)
	privateMessageBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	privateMessageObj := &MessageEntry{}
	rr := bytes.NewReader(privateMessageBytes)
	DecodeFromBytes(privateMessageObj, rr)
	return privateMessageObj
}

func DBGetMessageEntry(db *badger.DB, snap *Snapshot,
	publicKey []byte, tstampNanos uint64) *MessageEntry {

	var ret *MessageEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetMessageEntryWithTxn(txn, snap, publicKey, tstampNanos)
		return nil
	})
	return ret
}

// Note this deletes the message for the sender *and* receiver since a mapping
// should exist for each.
func DBDeleteMessageEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, tstampNanos uint64) error {

	// First pull up the mapping that exists for the public key passed in.
	// If one doesn't exist then there's nothing to do.
	existingMessage := DBGetMessageEntryWithTxn(txn, snap, publicKey, tstampNanos)
	if existingMessage == nil {
		return nil
	}

	// When a message exists, delete the mapping for the sender and receiver.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForMessageEntry(publicKey, tstampNanos)); err != nil {
		return errors.Wrapf(err, "DBDeleteMessageEntryMappingsWithTxn: Deleting "+
			"sender mapping for public key %s and tstamp %d failed",
			PkToStringMainnet(publicKey), tstampNanos)
	}

	return nil
}

func DBDeleteMessageEntryMappings(handle *badger.DB, snap *Snapshot,
	publicKey []byte, tstampNanos uint64) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteMessageEntryMappingsWithTxn(txn, snap, publicKey, tstampNanos)
	})
}

func DBGetMessageEntriesForPublicKey(handle *badger.DB, publicKey []byte) (
	_privateMessages []*MessageEntry, _err error) {

	// Setting the prefix to a tstamp of zero should return all the messages
	// for the public key in sorted order since 0 << the minimum timestamp in
	// the db.
	prefix := _dbSeekPrefixForMessagePublicKey(publicKey)

	// Goes backwards to get messages in time sorted order.
	// Limit the number of keys to speed up load times.
	_, valuesFound := _enumerateKeysForPrefix(handle, prefix)

	privateMessages := []*MessageEntry{}
	for _, valBytes := range valuesFound {
		privateMessageObj := &MessageEntry{}
		rr := bytes.NewReader(valBytes)
		if exists, err := DecodeFromBytes(privateMessageObj, rr); !exists || err != nil {
			return nil, errors.Wrapf(
				err, "DBGetMessageEntriesForPublicKey: Problem decoding value: ")
		}

		privateMessages = append(privateMessages, privateMessageObj)
	}

	return privateMessages, nil
}

func _enumerateLimitedMessagesForMessagingKeysReversedWithTxn(
	txn *badger.Txn, messagingGroupEntries []*MessagingGroupEntry,
	limit uint64) (_privateMessages []*MessageEntry, _err error) {

	// Users can have many messaging keys. By default, a users has the base messaging key, which
	// is just their main public key. Users can also register messaging keys, e.g. keys like the
	// "default-key", which can be used by others when sending messages to the user. The final
	// category of messaging keys are group chats, which also introduce a new messaging key that
	// the user can use to decrypt messages. Overall, the user has many messaging keys and needs
	// to index messages from multiple prefixes. To do so, we will make badger iterators for each
	// messaging key and scan each valid message prefix in reverse to get messages sorted by timestamps.

	// Get seek prefixes for each messaging key, we will use them to define iterators for message prefix
	var prefixes [][]byte
	for _, keyEntry := range messagingGroupEntries {
		prefixes = append(prefixes, _dbSeekPrefixForMessagePublicKey(keyEntry.MessagingPublicKey[:]))
		//prefixes = append(prefixes, _dbSeekPrefixForMessagePartyPublicKey(keyEntry.MessagingPublicKey[:]))
	}

	// Initialize all iterators, add the 0xff byte to the seek prefix so that we can iterate backwards.
	var messagingIterators []*badger.Iterator
	for _, prefix := range prefixes {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		iterator := txn.NewIterator(opts)
		iterator.Seek(append(prefix, 0xff))
		defer iterator.Close()
		messagingIterators = append(messagingIterators, iterator)
	}

	// We will fetch at most (limit) messages.
	privateMessages := []*MessageEntry{}
	for ; limit > 0; limit-- {

		// This loop will find the latest message among all messaging keys.
		// To do so, we find the greatest timestamp from iterator keys.
		latestTimestamp := uint64(0)
		latestTimestampIndex := -1
		for ii := 0; ii < len(prefixes); ii++ {
			if !messagingIterators[ii].ValidForPrefix(prefixes[ii]) {
				continue
			}
			// Get the timestamp from the item key
			key := messagingIterators[ii].Item().Key()
			rr := bytes.NewReader(key[len(prefixes[ii]):])
			timestamp, err := ReadUvarint(rr)
			if err != nil {
				return nil, errors.Wrapf(err, "_enumerateLimitedMessagesForMessagingKeysReversedWithTxn: problem reading timestamp "+
					"for messaging iterator from prefix (%v) at key (%v)", prefixes[ii], messagingIterators[ii].Item().Key())
			}

			if timestamp > latestTimestamp {
				latestTimestampIndex = ii
				latestTimestamp = timestamp
			}
		}

		// Now that we found the latest message, let's decode and process it.
		if latestTimestampIndex == -1 {
			break
		} else {
			// Get the message bytes and decode the message.
			messageBytes, err := messagingIterators[latestTimestampIndex].Item().ValueCopy(nil)
			if err != nil {
				return nil, errors.Wrapf(err, "_enumerateLimitedMessagesForMessagingKeysReversedWithTxn: Problem copying "+
					"value from messaging iterator from prefix (%v) at key (%v)",
					prefixes[latestTimestampIndex], messagingIterators[latestTimestampIndex].Item().Key())
			}
			message := &MessageEntry{}
			rr := bytes.NewReader(messageBytes)
			if exists, err := DecodeFromBytes(message, rr); !exists || err != nil {
				return nil, errors.Wrapf(err, "_enumerateLimitedMessagesForMessagingKeysReversedWithTxn: Problem decoding message "+
					"from messaging iterator from prefix (%v) at key (%v)",
					prefixes[latestTimestampIndex], messagingIterators[latestTimestampIndex].Item().Key())
			}
			// Add the message to the list of fetched messages
			privateMessages = append(privateMessages, message)
			messagingIterators[latestTimestampIndex].Next()
		}
	}

	return privateMessages, nil
}

func DBGetLimitedMessageForMessagingKeys(handle *badger.DB, messagingKeys []*MessagingGroupEntry, limit uint64) (
	_privateMessages []*MessageEntry, _err error) {

	// Setting the prefix to a tstamp of zero should return all the messages
	// for the public key in sorted order since 0 << the minimum timestamp in
	// the db.

	// Goes backwards to get messages in time sorted order.
	// Limit the number of keys to speed up load times.
	// Get all user messaging keys.

	err := handle.Update(func(txn *badger.Txn) error {
		var err error
		_privateMessages, err = _enumerateLimitedMessagesForMessagingKeysReversedWithTxn(txn, messagingKeys, limit)
		if err != nil {
			return errors.Wrapf(err, "DBGetLimitedMessageForMessagingKeys: problem getting user messages")
		}

		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "DbGetLimitedMessageAndPartyEntriesForPublicKey: problem getting user messages in txn")
	}

	return _privateMessages, nil
}

// -------------------------------------------------------------------------------------
// MessagingGroupEntry mapping functions
// <prefix, OwnerPublicKey (33 bytes) || GroupKeyName (32 bytes)> -> <MessagingGroupEntry>
// -------------------------------------------------------------------------------------

func _dbKeyForMessagingGroupEntry(messagingGroupEntry *MessagingGroupKey) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixMessagingGroupEntriesByOwnerPubKeyAndGroupKeyName...)
	key := append(prefixCopy, messagingGroupEntry.OwnerPublicKey[:]...)
	key = append(key, messagingGroupEntry.GroupKeyName[:]...)
	return key
}

func _dbSeekPrefixForMessagingGroupEntry(ownerPublicKey *PublicKey) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixMessagingGroupEntriesByOwnerPubKeyAndGroupKeyName...)
	return append(prefixCopy, ownerPublicKey[:]...)
}

func DBPutMessagingGroupEntryWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	ownerPublicKey *PublicKey, messagingGroupEntry *MessagingGroupEntry) error {

	messagingKey := &MessagingGroupKey{
		OwnerPublicKey: *ownerPublicKey,
		GroupKeyName:   *messagingGroupEntry.MessagingGroupKeyName,
	}
	if err := DBSetWithTxn(txn, snap, _dbKeyForMessagingGroupEntry(messagingKey), EncodeToBytes(blockHeight, messagingGroupEntry)); err != nil {
		return errors.Wrapf(err, "DBPutMessagingGroupEntryWithTxn: Problem adding messaging key entry mapping: ")
	}

	return nil
}

func DBPutMessagingGroupEntry(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	ownerPublicKey *PublicKey, messagingGroupEntry *MessagingGroupEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutMessagingGroupEntryWithTxn(txn, snap, blockHeight, ownerPublicKey, messagingGroupEntry)
	})
}

func DBGetMessagingGroupEntryWithTxn(txn *badger.Txn, snap *Snapshot,
	messagingGroupKey *MessagingGroupKey) *MessagingGroupEntry {

	key := _dbKeyForMessagingGroupEntry(messagingGroupKey)

	messagingGroupBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}
	messagingGroupEntry := &MessagingGroupEntry{}
	rr := bytes.NewReader(messagingGroupBytes)
	DecodeFromBytes(messagingGroupEntry, rr)
	return messagingGroupEntry
}

func DBGetMessagingGroupEntry(db *badger.DB, snap *Snapshot,
	messagingGroupKey *MessagingGroupKey) *MessagingGroupEntry {
	var ret *MessagingGroupEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetMessagingGroupEntryWithTxn(txn, snap, messagingGroupKey)
		return nil
	})
	return ret
}

func DBDeleteMessagingGroupEntryWithTxn(txn *badger.Txn, snap *Snapshot,
	messagingGroupKey *MessagingGroupKey) error {

	// First pull up the entry that exists for the messaging key.
	// If one doesn't exist then there's nothing to do.
	if entry := DBGetMessagingGroupEntryWithTxn(txn, snap, messagingGroupKey); entry == nil {
		return nil
	}

	// When a messaging key entry exists, delete it from the DB.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForMessagingGroupEntry(messagingGroupKey)); err != nil {
		return errors.Wrapf(err, "DBDeleteMessagingGroupEntryWithTxn: Deleting "+
			"entry for MessagingGroupKey failed: %v", messagingGroupKey)
	}

	return nil
}

func DBDeleteMessagingGroupEntry(handle *badger.DB, snap *Snapshot,
	messagingGroupKey *MessagingGroupKey) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteMessagingGroupEntryWithTxn(txn, snap, messagingGroupKey)
	})
}

func DBGetMessagingGroupEntriesForOwnerWithTxn(txn *badger.Txn, ownerPublicKey *PublicKey) (
	_messagingKeyEntries []*MessagingGroupEntry, _err error) {

	// Setting the prefix to owner's public key will allow us to fetch all messaging keys
	// for the user. We enumerate this prefix.
	prefix := _dbSeekPrefixForMessagingGroupEntry(ownerPublicKey)
	_, valuesFound, err := _enumerateKeysForPrefixWithTxn(txn, prefix)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetMessagingGroupEntriesForOwnerWithTxn: "+
			"problem enumerating messaging key entries for prefix (%v)", prefix)
	}

	// Decode found messaging key entries.
	messagingKeyEntries := []*MessagingGroupEntry{}
	for _, valBytes := range valuesFound {
		messagingKeyEntry := &MessagingGroupEntry{}
		rr := bytes.NewReader(valBytes)
		if exists, err := DecodeFromBytes(messagingKeyEntry, rr); !exists || err != nil {
			return nil, errors.Wrapf(err, "DBGetMessagingGroupEntriesForOwnerWithTxn: "+
				"problem decoding messaging key entry for public key (%v)", ownerPublicKey)
		}

		messagingKeyEntries = append(messagingKeyEntries, messagingKeyEntry)
	}

	return messagingKeyEntries, nil
}

func DBGetAllUserGroupEntiresWithTxn(txn *badger.Txn, ownerPublicKey []byte) ([]*MessagingGroupEntry, error) {
	// This function fetches all MessagingGroupEntries for the user from the DB. This includes the
	// base entry, the owner group entries, and the member group entries.

	// We will keep track of all group entries in this array.
	var userGroupEntries []*MessagingGroupEntry

	// First add the base messaging key.
	userGroupEntries = append(userGroupEntries, &MessagingGroupEntry{
		GroupOwnerPublicKey:   NewPublicKey(ownerPublicKey),
		MessagingPublicKey:    NewPublicKey(ownerPublicKey),
		MessagingGroupKeyName: BaseGroupKeyName(),
	})

	// Now add all the groups where this user is the owner
	ownerGroupEntries, err := DBGetMessagingGroupEntriesForOwnerWithTxn(txn, NewPublicKey(ownerPublicKey))
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetAllUserGroupEntiresWithTxn: problem getting messaging entries")
	}
	userGroupEntries = append(userGroupEntries, ownerGroupEntries...)

	// And add the groups where the user is a member
	memberGroupEntries, err := DBGetAllMessagingGroupEntriesForMemberWithTxn(txn, NewPublicKey(ownerPublicKey))
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetAllUserGroupEntiresWithTxn: problem getting recipient entries")
	}
	userGroupEntries = append(userGroupEntries, memberGroupEntries...)

	return userGroupEntries, nil
}

func DBGetAllUserGroupEntries(handle *badger.DB, ownerPublicKey []byte) ([]*MessagingGroupEntry, error) {
	var err error
	var messagingGroupEntries []*MessagingGroupEntry

	err = handle.View(func(txn *badger.Txn) error {
		messagingGroupEntries, err = DBGetAllUserGroupEntiresWithTxn(txn, ownerPublicKey)
		return err
	})
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetAllUserGroupEntries: problem getting user messaging keys")
	}
	return messagingGroupEntries, nil
}

// -------------------------------------------------------------------------------------
// Messaging recipient
// <prefix, public key, messaging public key > -> <HackedMessagingGroupEntry>
// -------------------------------------------------------------------------------------

func _dbKeyForMessagingGroupMember(memberPublicKey *PublicKey, groupMessagingPublicKey *PublicKey) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixMessagingGroupMetadataByMemberPubKeyAndGroupMessagingPubKey...)
	key := append(prefixCopy, memberPublicKey[:]...)
	key = append(key, groupMessagingPublicKey[:]...)
	return key
}

func _dbSeekPrefixForMessagingGroupMember(memberPublicKey *PublicKey) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixMessagingGroupMetadataByMemberPubKeyAndGroupMessagingPubKey...)
	return append(prefixCopy, memberPublicKey[:]...)
}

func DBPutMessagingGroupMemberWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	messagingGroupMember *MessagingGroupMember, groupOwnerPublicKey *PublicKey,
	messagingGroupEntry *MessagingGroupEntry) error {
	// Sanity-check that public keys have the correct length.

	if len(messagingGroupMember.EncryptedKey) < btcec.PrivKeyBytesLen {
		return fmt.Errorf("DBPutMessagingGroupMemberWithTxn: Problem getting recipient "+
			"entry for public key (%v)", messagingGroupMember.GroupMemberPublicKey)
	}

	// Entries for group members are stored as MessagingGroupEntries where the only member in
	// the entry is the member specified. This is a bit of a hack to allow us to store a "back-reference"
	// to the GroupEntry inside the value of this field.
	memberGroupEntry := &MessagingGroupEntry{
		GroupOwnerPublicKey:   groupOwnerPublicKey,
		MessagingPublicKey:    messagingGroupEntry.MessagingPublicKey,
		MessagingGroupKeyName: messagingGroupEntry.MessagingGroupKeyName,
		MessagingGroupMembers: []*MessagingGroupMember{
			messagingGroupMember,
		},
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForMessagingGroupMember(
		messagingGroupMember.GroupMemberPublicKey, messagingGroupEntry.MessagingPublicKey),
		EncodeToBytes(blockHeight, memberGroupEntry)); err != nil {

		return errors.Wrapf(err, "DBPutMessagingGroupMemberWithTxn: Problem setting messaging recipient with key (%v) "+
			"and entry (%v) in the db", _dbKeyForMessagingGroupMember(
			messagingGroupMember.GroupMemberPublicKey, messagingGroupEntry.MessagingPublicKey),
			EncodeToBytes(blockHeight, memberGroupEntry))
	}

	return nil
}

func DBPutMessagingGroupMember(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	messagingGroupMember *MessagingGroupMember, ownerPublicKey *PublicKey, messagingGroupEntry *MessagingGroupEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutMessagingGroupMemberWithTxn(txn, snap, blockHeight, messagingGroupMember, ownerPublicKey, messagingGroupEntry)
	})
}

func DBGetMessagingGroupMemberWithTxn(txn *badger.Txn, snap *Snapshot, messagingGroupMember *MessagingGroupMember,
	messagingGroupEntry *MessagingGroupEntry) *MessagingGroupEntry {

	key := _dbKeyForMessagingGroupMember(
		messagingGroupMember.GroupMemberPublicKey, messagingGroupEntry.MessagingPublicKey)
	// This is a hacked MessagingGroupEntry that contains a single member entry
	// for the member we're fetching in the members list.
	messagingGroupMemberEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}
	messagingGroupMemberEntry := &MessagingGroupEntry{}
	rr := bytes.NewReader(messagingGroupMemberEntryBytes)
	DecodeFromBytes(messagingGroupMemberEntry, rr)

	return messagingGroupMemberEntry
}

func DBGetMessagingMember(db *badger.DB, snap *Snapshot, messagingMember *MessagingGroupMember,
	messagingGroupEntry *MessagingGroupEntry) *MessagingGroupEntry {

	var ret *MessagingGroupEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetMessagingGroupMemberWithTxn(txn, snap, messagingMember, messagingGroupEntry)
		return nil
	})
	return ret
}

func DBGetAllMessagingGroupEntriesForMemberWithTxn(txn *badger.Txn, ownerPublicKey *PublicKey) (
	[]*MessagingGroupEntry, error) {

	// This function is used to fetch all messaging
	var messagingGroupEntries []*MessagingGroupEntry
	prefix := _dbSeekPrefixForMessagingGroupMember(ownerPublicKey)
	_, valuesFound, err := _enumerateKeysForPrefixWithTxn(txn, prefix)
	if err != nil {
		return nil, errors.Wrapf(err, "DBGetAllMessagingGroupEntriesForMemberWithTxn: "+
			"problem enumerating messaging key entries for prefix (%v)", prefix)
	}

	for _, valBytes := range valuesFound {
		messagingGroupEntry := &MessagingGroupEntry{}
		rr := bytes.NewReader(valBytes)
		if exists, err := DecodeFromBytes(messagingGroupEntry, rr); !exists || err != nil {
			return nil, errors.Wrapf(err, "DBGetAllMessagingGroupEntriesForMemberWithTxn: problem reading "+
				"an entry from DB")
		}

		messagingGroupEntries = append(messagingGroupEntries, messagingGroupEntry)
	}

	return messagingGroupEntries, nil
}

// Note this deletes the message for the sender *and* receiver since a mapping
// should exist for each.
func DBDeleteMessagingGroupMemberMappingWithTxn(txn *badger.Txn, snap *Snapshot,
	messagingGroupMember *MessagingGroupMember, messagingGroupEntry *MessagingGroupEntry) error {

	// First pull up the mapping that exists for the public key passed in.
	// If one doesn't exist then there's nothing to do.
	existingMember := DBGetMessagingGroupMemberWithTxn(txn, snap, messagingGroupMember, messagingGroupEntry)
	if existingMember == nil {
		return nil
	}

	// When a message exists, delete the mapping for the sender and receiver.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForMessagingGroupMember(
		messagingGroupMember.GroupMemberPublicKey, messagingGroupEntry.MessagingPublicKey)); err != nil {

		return errors.Wrapf(err, "DBDeleteMessagingGroupMemberMappingWithTxn: Deleting mapping for public key %v "+
			"and messaging public key %v failed", messagingGroupMember.GroupMemberPublicKey[:],
			messagingGroupEntry.MessagingPublicKey[:])
	}

	return nil
}

func DBDeleteMessagingGroupMemberMappings(handle *badger.DB, snap *Snapshot,
	messagingGroupMember *MessagingGroupMember, messagingGroupEntry *MessagingGroupEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteMessagingGroupMemberMappingWithTxn(txn, snap, messagingGroupMember, messagingGroupEntry)
	})
}

// -------------------------------------------------------------------------------------
// Forbidden block signature public key functions
// <prefix_id, public key> -> <>
// -------------------------------------------------------------------------------------

func _dbKeyForForbiddenBlockSignaturePubKeys(publicKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixForbiddenBlockSignaturePubKeys...)
	key := append(prefixCopy, publicKey...)
	return key
}

func DbPutForbiddenBlockSignaturePubKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte) error {

	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutForbiddenBlockSignaturePubKeyWithTxn: Forbidden public key "+
			"length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForForbiddenBlockSignaturePubKeys(publicKey), []byte{}); err != nil {
		return errors.Wrapf(err, "DbPutForbiddenBlockSignaturePubKeyWithTxn: Problem adding mapping for sender: ")
	}

	return nil
}

func DbPutForbiddenBlockSignaturePubKey(handle *badger.DB, snap *Snapshot, publicKey []byte) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutForbiddenBlockSignaturePubKeyWithTxn(txn, snap, publicKey)
	})
}

func DbGetForbiddenBlockSignaturePubKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte) []byte {

	key := _dbKeyForForbiddenBlockSignaturePubKeys(publicKey)
	_, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	// Typically, we return a DB entry here, but we don't store anything for this mapping.
	// We use this function instead of one returning true / false for feature consistency.
	return []byte{}
}

func DbGetForbiddenBlockSignaturePubKey(db *badger.DB, snap *Snapshot, publicKey []byte) []byte {
	var ret []byte
	db.View(func(txn *badger.Txn) error {
		ret = DbGetForbiddenBlockSignaturePubKeyWithTxn(txn, snap, publicKey)
		return nil
	})
	return ret
}

func DbDeleteForbiddenBlockSignaturePubKeyWithTxn(
	txn *badger.Txn, snap *Snapshot, publicKey []byte) error {

	existingEntry := DbGetForbiddenBlockSignaturePubKeyWithTxn(txn, snap, publicKey)
	if existingEntry == nil {
		return nil
	}

	if err := DBDeleteWithTxn(txn, snap, _dbKeyForForbiddenBlockSignaturePubKeys(publicKey)); err != nil {
		return errors.Wrapf(err, "DbDeleteForbiddenBlockSignaturePubKeyWithTxn: Deleting "+
			"sender mapping for public key %s failed", PkToStringMainnet(publicKey))
	}

	return nil
}

func DbDeleteForbiddenBlockSignaturePubKey(
	handle *badger.DB, snap *Snapshot, publicKey []byte) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteForbiddenBlockSignaturePubKeyWithTxn(txn, snap, publicKey)
	})
}

// -------------------------------------------------------------------------------------
// Likes mapping functions
// 		<prefix_id, user pub key [33]byte, liked post BlockHash> -> <>
// 		<prefix_id, liked post BlockHash, user pub key [33]byte> -> <>
// -------------------------------------------------------------------------------------

func _dbKeyForLikerPubKeyToLikedPostHashMapping(
	userPubKey []byte, likedPostHash BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixLikerPubKeyToLikedPostHash...)
	key := append(prefixCopy, userPubKey...)
	key = append(key, likedPostHash[:]...)
	return key
}

func _dbKeyForLikedPostHashToLikerPubKeyMapping(
	likedPostHash BlockHash, userPubKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixLikedPostHashToLikerPubKey...)
	key := append(prefixCopy, likedPostHash[:]...)
	key = append(key, userPubKey...)
	return key
}

func _dbSeekPrefixForPostHashesYouLike(yourPubKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixLikerPubKeyToLikedPostHash...)
	return append(prefixCopy, yourPubKey...)
}

func _dbSeekPrefixForLikerPubKeysLikingAPostHash(likedPostHash BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixLikedPostHashToLikerPubKey...)
	return append(prefixCopy, likedPostHash[:]...)
}

// Note that this adds a mapping for the user *and* the liked post.
func DbPutLikeMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	userPubKey []byte, likedPostHash BlockHash) error {

	if len(userPubKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutLikeMappingsWithTxn: User public key "+
			"length %d != %d", len(userPubKey), btcec.PubKeyBytesLenCompressed)
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForLikerPubKeyToLikedPostHashMapping(
		userPubKey, likedPostHash), []byte{}); err != nil {

		return errors.Wrapf(
			err, "DbPutLikeMappingsWithTxn: Problem adding user to liked post mapping: ")
	}
	if err := DBSetWithTxn(txn, snap, _dbKeyForLikedPostHashToLikerPubKeyMapping(
		likedPostHash, userPubKey), []byte{}); err != nil {

		return errors.Wrapf(
			err, "DbPutLikeMappingsWithTxn: Problem adding liked post to user mapping: ")
	}

	return nil
}

func DbPutLikeMappings(handle *badger.DB, snap *Snapshot,
	userPubKey []byte, likedPostHash BlockHash) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutLikeMappingsWithTxn(txn, snap, userPubKey, likedPostHash)
	})
}

func DbGetLikerPubKeyToLikedPostHashMappingWithTxn(txn *badger.Txn,
	snap *Snapshot, userPubKey []byte, likedPostHash BlockHash) []byte {

	key := _dbKeyForLikerPubKeyToLikedPostHashMapping(userPubKey, likedPostHash)
	_, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	// Typically, we return a DB entry here, but we don't store anything for like mappings.
	// We use this function instead of one returning true / false for feature consistency.
	return []byte{}
}

func DbGetLikerPubKeyToLikedPostHashMapping(
	db *badger.DB, snap *Snapshot, userPubKey []byte, likedPostHash BlockHash) []byte {
	var ret []byte
	db.View(func(txn *badger.Txn) error {
		ret = DbGetLikerPubKeyToLikedPostHashMappingWithTxn(txn, snap, userPubKey, likedPostHash)
		return nil
	})
	return ret
}

// Note this deletes the like for the user *and* the liked post since a mapping
// should exist for each.
func DbDeleteLikeMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	userPubKey []byte, likedPostHash BlockHash) error {

	// First check that a mapping exists. If one doesn't exist then there's nothing to do.
	existingMapping := DbGetLikerPubKeyToLikedPostHashMappingWithTxn(
		txn, snap, userPubKey, likedPostHash)
	if existingMapping == nil {
		return nil
	}

	// When a message exists, delete the mapping for the sender and receiver.
	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForLikerPubKeyToLikedPostHashMapping(userPubKey, likedPostHash)); err != nil {
		return errors.Wrapf(err, "DbDeleteLikeMappingsWithTxn: Deleting "+
			"userPubKey %s and likedPostHash %s failed",
			PkToStringBoth(userPubKey), likedPostHash)
	}
	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForLikedPostHashToLikerPubKeyMapping(likedPostHash, userPubKey)); err != nil {
		return errors.Wrapf(err, "DbDeleteLikeMappingsWithTxn: Deleting "+
			"likedPostHash %s and userPubKey %s failed",
			PkToStringBoth(likedPostHash[:]), PkToStringBoth(userPubKey))
	}

	return nil
}

func DbDeleteLikeMappings(handle *badger.DB, snap *Snapshot,
	userPubKey []byte, likedPostHash BlockHash) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteLikeMappingsWithTxn(txn, snap, userPubKey, likedPostHash)
	})
}

func DbGetPostHashesYouLike(handle *badger.DB, yourPublicKey []byte) (
	_postHashes []*BlockHash, _err error) {

	prefix := _dbSeekPrefixForPostHashesYouLike(yourPublicKey)
	keysFound, _ := _enumerateKeysForPrefix(handle, prefix)

	postHashesYouLike := []*BlockHash{}
	for _, keyBytes := range keysFound {
		// We must slice off the first byte and userPubKey to get the likedPostHash.
		postHash := &BlockHash{}
		copy(postHash[:], keyBytes[1+btcec.PubKeyBytesLenCompressed:])
		postHashesYouLike = append(postHashesYouLike, postHash)
	}

	return postHashesYouLike, nil
}

func DbGetLikerPubKeysLikingAPostHash(handle *badger.DB, likedPostHash BlockHash) (
	_pubKeys [][]byte, _err error) {

	prefix := _dbSeekPrefixForLikerPubKeysLikingAPostHash(likedPostHash)
	keysFound, _ := _enumerateKeysForPrefix(handle, prefix)

	userPubKeys := [][]byte{}
	for _, keyBytes := range keysFound {
		// We must slice off the first byte and likedPostHash to get the userPubKey.
		userPubKey := keyBytes[1+HashSizeBytes:]
		userPubKeys = append(userPubKeys, userPubKey)
	}

	return userPubKeys, nil
}

// -------------------------------------------------------------------------------------
// Reposts mapping functions
// 		<prefix_id, user pub key [33]byte, reposted post BlockHash> -> <>
// 		<prefix_id, reposted post BlockHash, user pub key [33]byte> -> <>
// -------------------------------------------------------------------------------------
//PrefixReposterPubKeyRepostedPostHashToRepostPostHash
func _dbKeyForReposterPubKeyRepostedPostHashToRepostPostHash(userPubKey []byte, repostedPostHash BlockHash, repostPostHash BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixReposterPubKeyRepostedPostHashToRepostPostHash...)
	key := append(prefixCopy, userPubKey...)
	key = append(key, repostedPostHash[:]...)
	key = append(key, repostPostHash[:]...)
	return key
}

// This is a little hacky but we can save space by encoding RepostEntry entirely in the prefix []byte{39} keys.
// _dbKeyForReposterPubKeyRepostedPostHashToRepostEntry decodes these keys into RepostEntry.
func _dbKeyForReposterPubKeyRepostedPostHashToRepostEntry(key []byte) *RepostEntry {
	if len(key) != 1+33+32+32 {
		return nil
	}

	entry := &RepostEntry{}
	entry.ReposterPubKey = key[1:34]
	entry.RepostedPostHash = NewBlockHash(key[34:66])
	entry.RepostPostHash = NewBlockHash(key[66:98])
	return entry
}

func _dbSeekKeyForReposterPubKeyRepostedPostHashToRepostPostHash(userPubKey []byte, repostedPostHash BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixReposterPubKeyRepostedPostHashToRepostPostHash...)
	key := append(prefixCopy, userPubKey...)
	key = append(key, repostedPostHash[:]...)
	return key
}

func _dbSeekPrefixForPostHashesYouRepost(yourPubKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixReposterPubKeyRepostedPostHashToRepostPostHash...)
	return append(prefixCopy, yourPubKey...)
}

//PrefixRepostedPostHashReposterPubKey
func _dbKeyForRepostedPostHashReposterPubKey(repostedPostHash *BlockHash, reposterPubKey []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixRepostedPostHashReposterPubKey...)
	key := append(prefixCopy, repostedPostHash[:]...)
	key = append(key, reposterPubKey...)
	return key
}

// **For quoted reposts**
//PrefixRepostedPostHashReposterPubKeyRepostPostHash
func _dbKeyForRepostedPostHashReposterPubKeyRepostPostHash(
	repostedPostHash *BlockHash, reposterPubKey []byte, repostPostHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixRepostedPostHashReposterPubKeyRepostPostHash...)
	key := append(prefixCopy, repostedPostHash[:]...)
	key = append(key, reposterPubKey...)
	key = append(key, repostPostHash[:]...)
	return key
}

// Note that this adds a mapping for the user *and* the reposted post.
func DbPutRepostMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	repostEntry RepostEntry) error {

	if len(repostEntry.ReposterPubKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutRepostMappingsWithTxn: User public key "+
			"length %d != %d", len(repostEntry.ReposterPubKey), btcec.PubKeyBytesLenCompressed)
	}
	if repostEntry.RepostedPostHash == nil {
		return fmt.Errorf("DbPutRepostMappingsWithTxn: Reposted post hash cannot be nil")
	}
	if repostEntry.RepostPostHash == nil {
		return fmt.Errorf("DbPutRepostMappingsWithTxn: Repost post hash cannot be nil")
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForReposterPubKeyRepostedPostHashToRepostPostHash(
		repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash, *repostEntry.RepostPostHash), []byte{}); err != nil {

		return errors.Wrapf(
			err, "DbPutRepostMappingsWithTxn: Problem adding user to reposted post mapping: ")
	}

	return nil
}

func DbPutRepostMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	userPubKey []byte, repostedPostHash BlockHash, repostEntry RepostEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutRepostMappingsWithTxn(txn, snap, blockHeight, repostEntry)
	})
}

func DbGetReposterPubKeyRepostedPostHashToRepostEntryWithTxn(txn *badger.Txn,
	snap *Snapshot, userPubKey []byte, repostedPostHash BlockHash) *RepostEntry {

	key := _dbSeekKeyForReposterPubKeyRepostedPostHashToRepostPostHash(userPubKey, repostedPostHash)
	keysFound, _, err := _enumerateKeysForPrefixWithTxn(txn, key)
	if err != nil {
		return nil
	}
	// We select the RepostEntry with the "smallest" repostHash. We can't tell which
	// one is preferred, so we just return the first one.
	for _, keyBytes := range keysFound {
		return _dbKeyForReposterPubKeyRepostedPostHashToRepostEntry(keyBytes)
		// We must slice off the first byte and userPubKey to get the repostedPostHash.
	}
	return nil
}

func DbReposterPubKeyRepostedPostHashToRepostEntry(db *badger.DB,
	snap *Snapshot, userPubKey []byte, repostedPostHash BlockHash) *RepostEntry {

	var ret *RepostEntry
	db.View(func(txn *badger.Txn) error {
		ret = DbGetReposterPubKeyRepostedPostHashToRepostEntryWithTxn(txn, snap, userPubKey, repostedPostHash)
		return nil
	})
	return ret
}

// Note this deletes the repost for the user *and* the reposted post since a mapping
// should exist for each.
func DbDeleteRepostMappingsWithTxn(txn *badger.Txn, snap *Snapshot, repostEntry RepostEntry) error {

	// First check that a mapping exists. If one doesn't exist then there's nothing to do.
	_, err := DBGetWithTxn(txn, snap, _dbKeyForReposterPubKeyRepostedPostHashToRepostPostHash(
		repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash, *repostEntry.RepostPostHash))
	if err != nil {
		return nil
	}

	// When a repost exists, delete the repost entry mapping.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForReposterPubKeyRepostedPostHashToRepostPostHash(
		repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash, *repostEntry.RepostPostHash)); err != nil {
		return errors.Wrapf(err, "DbDeleteRepostMappingsWithTxn: Deleting "+
			"user public key %s and reposted post hash %v and repost post hash %v failed",
			PkToStringMainnet(repostEntry.ReposterPubKey[:]), repostEntry.RepostedPostHash[:], repostEntry.RepostPostHash[:])
	}
	return nil
}

func DbDeleteAllRepostMappingsWithTxn(txn *badger.Txn, snap *Snapshot, userPubKey []byte, repostedPostHash BlockHash) error {

	key := _dbSeekKeyForReposterPubKeyRepostedPostHashToRepostPostHash(userPubKey, repostedPostHash)
	keysFound, _, err := _enumerateKeysForPrefixWithTxn(txn, key)
	if err != nil {
		return nil
	}
	for _, keyBytes := range keysFound {
		if err := DBDeleteWithTxn(txn, snap, keyBytes); err != nil {
			return errors.Wrapf(err, "DbDeleteAllRepostMappingsWithTxn: Problem deleting a repost entry "+
				"with key (%v)", key)
		}
	}
	return nil
}

func DbGetPostHashesYouRepost(handle *badger.DB, yourPublicKey []byte) (
	_postHashes []*BlockHash, _err error) {

	prefix := _dbSeekPrefixForPostHashesYouRepost(yourPublicKey)
	keysFound, _ := _enumerateKeysForPrefix(handle, prefix)

	postHashesYouRepost := []*BlockHash{}
	for _, keyBytes := range keysFound {
		// We must slice off the first byte and userPubKey to get the repostedPostHash.
		postHash := &BlockHash{}
		copy(postHash[:], keyBytes[1+btcec.PubKeyBytesLenCompressed:])
		postHashesYouRepost = append(postHashesYouRepost, postHash)
	}

	return postHashesYouRepost, nil
}

// -------------------------------------------------------------------------------------
// Follows mapping functions
// 		<prefix_id, follower pub key [33]byte, followed pub key [33]byte> -> <>
// 		<prefix_id, followed pub key [33]byte, follower pub key [33]byte> -> <>
// -------------------------------------------------------------------------------------

func _dbKeyForFollowerToFollowedMapping(
	followerPKID *PKID, followedPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixFollowerPKIDToFollowedPKID...)
	key := append(prefixCopy, followerPKID[:]...)
	key = append(key, followedPKID[:]...)
	return key
}

func _dbKeyForFollowedToFollowerMapping(
	followedPKID *PKID, followerPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixFollowedPKIDToFollowerPKID...)
	key := append(prefixCopy, followedPKID[:]...)
	key = append(key, followerPKID[:]...)
	return key
}

func _dbSeekPrefixForPKIDsYouFollow(yourPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixFollowerPKIDToFollowedPKID...)
	return append(prefixCopy, yourPKID[:]...)
}

func _dbSeekPrefixForPKIDsFollowingYou(yourPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixFollowedPKIDToFollowerPKID...)
	return append(prefixCopy, yourPKID[:]...)
}

// Note that this adds a mapping for the follower *and* the pub key being followed.
func DbPutFollowMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	followerPKID *PKID, followedPKID *PKID) error {

	if len(followerPKID) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutFollowMappingsWithTxn: Follower PKID "+
			"length %d != %d", len(followerPKID[:]), btcec.PubKeyBytesLenCompressed)
	}
	if len(followedPKID) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutFollowMappingsWithTxn: Followed PKID "+
			"length %d != %d", len(followerPKID), btcec.PubKeyBytesLenCompressed)
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForFollowerToFollowedMapping(
		followerPKID, followedPKID), []byte{}); err != nil {

		return errors.Wrapf(
			err, "DbPutFollowMappingsWithTxn: Problem adding follower to followed mapping: ")
	}
	if err := DBSetWithTxn(txn, snap, _dbKeyForFollowedToFollowerMapping(
		followedPKID, followerPKID), []byte{}); err != nil {

		return errors.Wrapf(
			err, "DbPutFollowMappingsWithTxn: Problem adding followed to follower mapping: ")
	}

	return nil
}

func DbPutFollowMappings(handle *badger.DB, snap *Snapshot,
	followerPKID *PKID, followedPKID *PKID) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutFollowMappingsWithTxn(txn, snap, followerPKID, followedPKID)
	})
}

func DbGetFollowerToFollowedMappingWithTxn(txn *badger.Txn,
	snap *Snapshot, followerPKID *PKID, followedPKID *PKID) []byte {

	key := _dbKeyForFollowerToFollowedMapping(followerPKID, followedPKID)
	_, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	// Typically we return a DB entry here but we don't store anything for like mappings.
	// We use this function instead of one returning true / false for feature consistency.
	return []byte{}
}

func DbGetFollowerToFollowedMapping(db *badger.DB, snap *Snapshot,
	followerPKID *PKID, followedPKID *PKID) []byte {

	var ret []byte
	db.View(func(txn *badger.Txn) error {
		ret = DbGetFollowerToFollowedMappingWithTxn(txn, snap, followerPKID, followedPKID)
		return nil
	})
	return ret
}

// Note this deletes the follow for the follower *and* followed since a mapping
// should exist for each.
func DbDeleteFollowMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	followerPKID *PKID, followedPKID *PKID) error {

	// First check that a mapping exists for the PKIDs passed in.
	// If one doesn't exist then there's nothing to do.
	existingMapping := DbGetFollowerToFollowedMappingWithTxn(
		txn, snap, followerPKID, followedPKID)
	if existingMapping == nil {
		return nil
	}

	// When a message exists, delete the mapping for the sender and receiver.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForFollowerToFollowedMapping(followerPKID, followedPKID)); err != nil {
		return errors.Wrapf(err, "DbDeleteFollowMappingsWithTxn: Deleting "+
			"followerPKID %s and followedPKID %s failed",
			PkToStringMainnet(followerPKID[:]), PkToStringMainnet(followedPKID[:]))
	}
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForFollowedToFollowerMapping(followedPKID, followerPKID)); err != nil {
		return errors.Wrapf(err, "DbDeleteFollowMappingsWithTxn: Deleting "+
			"followedPKID %s and followerPKID %s failed",
			PkToStringMainnet(followedPKID[:]), PkToStringMainnet(followerPKID[:]))
	}

	return nil
}

func DbDeleteFollowMappings(handle *badger.DB, snap *Snapshot,
	followerPKID *PKID, followedPKID *PKID) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteFollowMappingsWithTxn(txn, snap, followerPKID, followedPKID)
	})
}

func DbGetPKIDsYouFollow(handle *badger.DB, yourPKID *PKID) (
	_pkids []*PKID, _err error) {

	prefix := _dbSeekPrefixForPKIDsYouFollow(yourPKID)
	keysFound, _ := _enumerateKeysForPrefix(handle, prefix)

	pkidsYouFollow := []*PKID{}
	for _, keyBytes := range keysFound {
		// We must slice off the first byte and followerPKID to get the followedPKID.
		followedPKIDBytes := keyBytes[1+btcec.PubKeyBytesLenCompressed:]
		followedPKID := &PKID{}
		copy(followedPKID[:], followedPKIDBytes)
		pkidsYouFollow = append(pkidsYouFollow, followedPKID)
	}

	return pkidsYouFollow, nil
}

func DbGetPKIDsFollowingYou(handle *badger.DB, yourPKID *PKID) (
	_pkids []*PKID, _err error) {

	prefix := _dbSeekPrefixForPKIDsFollowingYou(yourPKID)
	keysFound, _ := _enumerateKeysForPrefix(handle, prefix)

	pkidsFollowingYou := []*PKID{}
	for _, keyBytes := range keysFound {
		// We must slice off the first byte and followedPKID to get the followerPKID.
		followerPKIDBytes := keyBytes[1+btcec.PubKeyBytesLenCompressed:]
		followerPKID := &PKID{}
		copy(followerPKID[:], followerPKIDBytes)
		pkidsFollowingYou = append(pkidsFollowingYou, followerPKID)
	}

	return pkidsFollowingYou, nil
}

func DbGetPubKeysYouFollow(handle *badger.DB, snap *Snapshot, yourPubKey []byte) (
	_pubKeys [][]byte, _err error) {

	// Get the PKID for the pub key
	yourPKID := DBGetPKIDEntryForPublicKey(handle, snap, yourPubKey)
	followPKIDs, err := DbGetPKIDsYouFollow(handle, yourPKID.PKID)
	if err != nil {
		return nil, errors.Wrap(err, "DbGetPubKeysYouFollow: ")
	}

	// Convert the pkids to public keys
	followPubKeys := [][]byte{}
	for _, fpkidIter := range followPKIDs {
		fpkid := fpkidIter
		followPk := DBGetPublicKeyForPKID(handle, snap, fpkid)
		followPubKeys = append(followPubKeys, followPk)
	}

	return followPubKeys, nil
}

func DbGetPubKeysFollowingYou(handle *badger.DB, snap *Snapshot, yourPubKey []byte) (
	_pubKeys [][]byte, _err error) {

	// Get the PKID for the pub key
	yourPKID := DBGetPKIDEntryForPublicKey(handle, snap, yourPubKey)
	followPKIDs, err := DbGetPKIDsFollowingYou(handle, yourPKID.PKID)
	if err != nil {
		return nil, errors.Wrap(err, "DbGetPubKeysFollowingYou: ")
	}

	// Convert the pkids to public keys
	followPubKeys := [][]byte{}
	for _, fpkidIter := range followPKIDs {
		fpkid := fpkidIter
		followPk := DBGetPublicKeyForPKID(handle, snap, fpkid)
		followPubKeys = append(followPubKeys, followPk)
	}

	return followPubKeys, nil
}

// -------------------------------------------------------------------------------------
// Diamonds mapping functions
//  <prefix_id, DiamondReceiverPKID [33]byte, DiamondSenderPKID [33]byte, posthash> -> <[]byte{DiamondLevel}>
// -------------------------------------------------------------------------------------

func _dbKeyForDiamondReceiverToDiamondSenderMapping(diamondEntry *DiamondEntry) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondReceiverPKIDDiamondSenderPKIDPostHash...)
	key := append(prefixCopy, diamondEntry.ReceiverPKID[:]...)
	key = append(key, diamondEntry.SenderPKID[:]...)
	key = append(key, diamondEntry.DiamondPostHash[:]...)
	return key
}

func _dbKeyForDiamondReceiverToDiamondSenderMappingWithoutEntry(
	diamondReceiverPKID *PKID, diamondSenderPKID *PKID, diamondPostHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondReceiverPKIDDiamondSenderPKIDPostHash...)
	key := append(prefixCopy, diamondReceiverPKID[:]...)
	key = append(key, diamondSenderPKID[:]...)
	key = append(key, diamondPostHash[:]...)
	return key
}

func _dbKeyForDiamondedPostHashDiamonderPKIDDiamondLevel(diamondEntry *DiamondEntry) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondedPostHashDiamonderPKIDDiamondLevel...)
	key := append(prefixCopy, diamondEntry.DiamondPostHash[:]...)
	key = append(key, diamondEntry.SenderPKID[:]...)
	// Diamond level is an int64 in extraData but it forced to be non-negative in consensus.
	key = append(key, EncodeUint64(uint64(diamondEntry.DiamondLevel))...)
	return key
}

func _dbSeekPrefixForPKIDsThatDiamondedYou(yourPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondReceiverPKIDDiamondSenderPKIDPostHash...)
	return append(prefixCopy, yourPKID[:]...)
}

func _dbKeyForDiamondSenderToDiamondReceiverMapping(diamondEntry *DiamondEntry) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondSenderPKIDDiamondReceiverPKIDPostHash...)
	key := append(prefixCopy, diamondEntry.SenderPKID[:]...)
	key = append(key, diamondEntry.ReceiverPKID[:]...)
	key = append(key, diamondEntry.DiamondPostHash[:]...)
	return key
}

func _dbKeyForDiamondSenderToDiamondReceiverMappingWithoutEntry(
	diamondReceiverPKID *PKID, diamondSenderPKID *PKID, diamondPostHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondSenderPKIDDiamondReceiverPKIDPostHash...)
	key := append(prefixCopy, diamondSenderPKID[:]...)
	key = append(key, diamondReceiverPKID[:]...)
	key = append(key, diamondPostHash[:]...)
	return key
}

func _dbSeekPrefixForPKIDsThatYouDiamonded(yourPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondSenderPKIDDiamondReceiverPKIDPostHash...)
	return append(prefixCopy, yourPKID[:]...)
}

func _dbSeekPrefixForReceiverPKIDAndSenderPKID(receiverPKID *PKID, senderPKID *PKID) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixDiamondReceiverPKIDDiamondSenderPKIDPostHash...)
	key := append(prefixCopy, receiverPKID[:]...)
	return append(key, senderPKID[:]...)
}

func DbPutDiamondMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	diamondEntry *DiamondEntry) error {

	if len(diamondEntry.ReceiverPKID) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutDiamondMappingsWithTxn: Receiver PKID "+
			"length %d != %d", len(diamondEntry.ReceiverPKID[:]), btcec.PubKeyBytesLenCompressed)
	}
	if len(diamondEntry.SenderPKID) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DbPutDiamondMappingsWithTxn: Sender PKID "+
			"length %d != %d", len(diamondEntry.SenderPKID), btcec.PubKeyBytesLenCompressed)
	}

	diamondEntryBytes := EncodeToBytes(blockHeight, diamondEntry)
	if err := DBSetWithTxn(txn, snap, _dbKeyForDiamondReceiverToDiamondSenderMapping(diamondEntry), diamondEntryBytes); err != nil {
		return errors.Wrapf(
			err, "DbPutDiamondMappingsWithTxn: Problem adding receiver to giver mapping: ")
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForDiamondSenderToDiamondReceiverMapping(diamondEntry), diamondEntryBytes); err != nil {
		return errors.Wrapf(err, "DbPutDiamondMappingsWithTxn: Problem adding sender to receiver mapping: ")
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForDiamondedPostHashDiamonderPKIDDiamondLevel(diamondEntry),
		[]byte{}); err != nil {
		return errors.Wrapf(
			err, "DbPutDiamondMappingsWithTxn: Problem adding DiamondedPostHash Diamonder Diamond Level mapping: ")
	}

	return nil
}

func DbPutDiamondMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	diamondEntry *DiamondEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutDiamondMappingsWithTxn(txn, snap, blockHeight, diamondEntry)
	})
}

func DbGetDiamondMappingsWithTxn(txn *badger.Txn, snap *Snapshot, diamondReceiverPKID *PKID,
	diamondSenderPKID *PKID, diamondPostHash *BlockHash) *DiamondEntry {

	key := _dbKeyForDiamondReceiverToDiamondSenderMappingWithoutEntry(
		diamondReceiverPKID, diamondSenderPKID, diamondPostHash)
	diamondEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	// We return the byte array stored for this diamond mapping. This mapping should only
	// hold one uint8 with a value between 1 and 5 but the caller is responsible for sanity
	// checking in order to maintain consistency with other DB functions that do not error.
	diamondEntry := &DiamondEntry{}
	rr := bytes.NewReader(diamondEntryBytes)
	DecodeFromBytes(diamondEntry, rr)
	return diamondEntry
}

func DbGetDiamondMappings(db *badger.DB, snap *Snapshot, diamondReceiverPKID *PKID,
	diamondSenderPKID *PKID, diamondPostHash *BlockHash) *DiamondEntry {

	var ret *DiamondEntry
	db.View(func(txn *badger.Txn) error {
		ret = DbGetDiamondMappingsWithTxn(
			txn, snap, diamondReceiverPKID, diamondSenderPKID, diamondPostHash)
		return nil
	})
	return ret
}

func DbDeleteDiamondMappingsWithTxn(txn *badger.Txn, snap *Snapshot, diamondEntry *DiamondEntry) error {

	// First check that a mapping exists for the PKIDs passed in.
	// If one doesn't exist then there's nothing to do.
	existingMapping := DbGetDiamondMappingsWithTxn(txn, snap,
		diamondEntry.ReceiverPKID, diamondEntry.SenderPKID, diamondEntry.DiamondPostHash)
	if existingMapping == nil {
		return nil
	}

	// When a DiamondEntry exists, delete the diamond mappings.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForDiamondReceiverToDiamondSenderMapping(diamondEntry)); err != nil {
		return errors.Wrapf(err, "DbDeleteDiamondMappingsWithTxn: Deleting "+
			"diamondReceiverPKID %s and diamondSenderPKID %s and diamondPostHash %s failed",
			PkToStringMainnet(diamondEntry.ReceiverPKID[:]),
			PkToStringMainnet(diamondEntry.SenderPKID[:]),
			diamondEntry.DiamondPostHash.String(),
		)
	}
	// When a DiamondEntry exists, delete the diamond mappings.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForDiamondedPostHashDiamonderPKIDDiamondLevel(diamondEntry)); err != nil {
		return errors.Wrapf(err, "DbDeleteDiamondMappingsWithTxn: Deleting "+
			"diamondedPostHash %s and diamonderPKID %s and diamondLevel %s failed",
			diamondEntry.DiamondPostHash.String(),
			PkToStringMainnet(diamondEntry.SenderPKID[:]),
			diamondEntry.DiamondPostHash.String(),
		)
	}

	if err := DBDeleteWithTxn(txn, snap, _dbKeyForDiamondSenderToDiamondReceiverMapping(diamondEntry)); err != nil {
		return errors.Wrapf(err, "DbDeleteDiamondMappingsWithTxn: Deleting "+
			"diamondSenderPKID %s and diamondReceiverPKID %s and diamondPostHash %s failed",
			PkToStringMainnet(diamondEntry.SenderPKID[:]),
			PkToStringMainnet(diamondEntry.ReceiverPKID[:]),
			diamondEntry.DiamondPostHash.String(),
		)
	}

	return nil
}

func DbDeleteDiamondMappings(handle *badger.DB, snap *Snapshot, diamondEntry *DiamondEntry) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteDiamondMappingsWithTxn(txn, snap, diamondEntry)
	})
}

// This function returns a map of PKIDs that gave diamonds to a list of DiamondEntrys
// that contain post hashes.
func DbGetPKIDsThatDiamondedYouMap(handle *badger.DB, yourPKID *PKID, fetchYouDiamonded bool) (
	_pkidToDiamondsMap map[PKID][]*DiamondEntry, _err error) {

	prefix := _dbSeekPrefixForPKIDsThatDiamondedYou(yourPKID)
	diamondSenderStartIdx := 1 + btcec.PubKeyBytesLenCompressed
	diamondSenderEndIdx := 1 + 2*btcec.PubKeyBytesLenCompressed
	diamondReceiverStartIdx := 1
	diamondReceiverEndIdx := 1 + btcec.PubKeyBytesLenCompressed
	if fetchYouDiamonded {
		prefix = _dbSeekPrefixForPKIDsThatYouDiamonded(yourPKID)
		diamondSenderStartIdx = 1
		diamondSenderEndIdx = 1 + btcec.PubKeyBytesLenCompressed
		diamondReceiverStartIdx = 1 + btcec.PubKeyBytesLenCompressed
		diamondReceiverEndIdx = 1 + 2*btcec.PubKeyBytesLenCompressed
	}
	keysFound, valsFound := _enumerateKeysForPrefix(handle, prefix)

	pkidsToDiamondEntryMap := make(map[PKID][]*DiamondEntry)
	for ii, keyBytes := range keysFound {
		// The DiamondEntry found must not be nil.
		diamondEntry := &DiamondEntry{}
		rr := bytes.NewReader(valsFound[ii])
		DecodeFromBytes(diamondEntry, rr)
		if diamondEntry == nil {
			return nil, fmt.Errorf(
				"DbGetPKIDsThatDiamondedYouMap: Found nil DiamondEntry for public key %v "+
					"and key bytes %#v when seeking; this should never happen",
				PkToStringMainnet(yourPKID[:]), keyBytes)
		}
		expectedDiamondKeyLen := 1 + 2*btcec.PubKeyBytesLenCompressed + HashSizeBytes
		if len(keyBytes) != expectedDiamondKeyLen {
			return nil, fmt.Errorf(
				"DbGetPKIDsThatDiamondedYouMap: Invalid key length %v should be %v",
				len(keyBytes), expectedDiamondKeyLen)
		}

		// Note: The code below is mainly just sanity-checking. Checking the key isn't actually
		// needed in this function, since all the information is duplicated in the entry.

		// Chop out the diamond sender PKID.
		diamondSenderPKIDBytes := keyBytes[diamondSenderStartIdx:diamondSenderEndIdx]
		diamondSenderPKID := &PKID{}
		copy(diamondSenderPKID[:], diamondSenderPKIDBytes)
		// It must match what's in the DiamondEntry
		if !reflect.DeepEqual(diamondSenderPKID, diamondEntry.SenderPKID) {
			return nil, fmt.Errorf(
				"DbGetPKIDsThatDiamondedYouMap: Sender PKID in DB %v did not "+
					"match Sender PKID in DiamondEntry %v; this should never happen",
				PkToStringBoth(diamondSenderPKID[:]), PkToStringBoth(diamondEntry.SenderPKID[:]))
		}

		// Chop out the diamond receiver PKID
		diamondReceiverPKIDBytes := keyBytes[diamondReceiverStartIdx:diamondReceiverEndIdx]
		diamondReceiverPKID := &PKID{}
		copy(diamondReceiverPKID[:], diamondReceiverPKIDBytes)
		// It must match what's in the DiamondEntry
		if !reflect.DeepEqual(diamondReceiverPKID, diamondEntry.ReceiverPKID) {
			return nil, fmt.Errorf(
				"DbGetPKIDsThatDiamondedYouMap: Receiver PKID in DB %v did not "+
					"match Receiver PKID in DiamondEntry %v; this should never happen",
				PkToStringBoth(diamondReceiverPKID[:]), PkToStringBoth(diamondEntry.ReceiverPKID[:]))
		}

		// Chop out the diamond post hash.
		diamondPostHashBytes := keyBytes[1+2*btcec.PubKeyBytesLenCompressed:]
		diamondPostHash := &BlockHash{}
		copy(diamondPostHash[:], diamondPostHashBytes)
		// It must match what's in the entry
		if *diamondPostHash != *diamondEntry.DiamondPostHash {
			return nil, fmt.Errorf(
				"DbGetPKIDsThatDiamondedYouMap: Post hash found in DB key %v "+
					"did not match post hash in DiamondEntry %v; this should never happen",
				diamondPostHash, diamondEntry.DiamondPostHash)
		}

		// If a map entry doesn't exist for this sender, create one.
		newListOfEntrys := pkidsToDiamondEntryMap[*diamondSenderPKID]
		newListOfEntrys = append(newListOfEntrys, diamondEntry)
		pkidsToDiamondEntryMap[*diamondSenderPKID] = newListOfEntrys
	}

	return pkidsToDiamondEntryMap, nil
}

// This function returns a list of DiamondEntrys given by giverPKID to receiverPKID that contain post hashes.
func DbGetDiamondEntriesForSenderToReceiver(handle *badger.DB, receiverPKID *PKID, senderPKID *PKID) (
	_diamondEntries []*DiamondEntry, _err error) {

	prefix := _dbSeekPrefixForReceiverPKIDAndSenderPKID(receiverPKID, senderPKID)
	keysFound, valsFound := _enumerateKeysForPrefix(handle, prefix)
	var diamondEntries []*DiamondEntry
	for ii, keyBytes := range keysFound {
		// The DiamondEntry found must not be nil.
		diamondEntry := &DiamondEntry{}
		rr := bytes.NewReader(valsFound[ii])

		if exists, err := DecodeFromBytes(diamondEntry, rr); !exists || err != nil || diamondEntry == nil {
			return nil, fmt.Errorf(
				"DbGetDiamondEntriesForGiverToReceiver: Found nil DiamondEntry for receiver key %v "+
					"and giver key %v when seeking; this should never happen",
				PkToStringMainnet(receiverPKID[:]), PkToStringMainnet(senderPKID[:]))
		}
		expectedDiamondKeyLen := 1 + 2*btcec.PubKeyBytesLenCompressed + HashSizeBytes
		if len(keyBytes) != expectedDiamondKeyLen {
			return nil, fmt.Errorf(
				"DbGetDiamondEntriesForGiverToReceiver: Invalid key length %v should be %v",
				len(keyBytes), expectedDiamondKeyLen)
		}

		// Note: The code below is mainly just sanity-checking. Checking the key isn't actually
		// needed in this function, since all the information is duplicated in the entry.

		// Chop out the diamond sender PKID.
		diamondSenderPKIDBytes := keyBytes[1+btcec.PubKeyBytesLenCompressed : 1+2*btcec.PubKeyBytesLenCompressed]
		diamondSenderPKID := &PKID{}
		copy(diamondSenderPKID[:], diamondSenderPKIDBytes)
		// It must match what's in the DiamondEntry
		if !reflect.DeepEqual(diamondSenderPKID, diamondEntry.SenderPKID) {
			return nil, fmt.Errorf(
				"DbGetDiamondEntriesForGiverToReceiver: Sender PKID in DB %v did not "+
					"match Sender PKID in DiamondEntry %v; this should never happen",
				PkToStringBoth(diamondSenderPKID[:]), PkToStringBoth(diamondEntry.SenderPKID[:]))
		}

		// Chop out the diamond post hash.
		diamondPostHashBytes := keyBytes[1+2*btcec.PubKeyBytesLenCompressed:]
		diamondPostHash := &BlockHash{}
		copy(diamondPostHash[:], diamondPostHashBytes)
		// It must match what's in the entry
		if *diamondPostHash != *diamondEntry.DiamondPostHash {
			return nil, fmt.Errorf(
				"DbGetDiamondEntriesForGiverToReceiver: Post hash found in DB key %v "+
					"did not match post hash in DiamondEntry %v; this should never happen",
				diamondPostHash, diamondEntry.DiamondPostHash)
		}
		// Append the diamond entry to the slice
		diamondEntries = append(diamondEntries, diamondEntry)
	}
	return diamondEntries, nil
}

// -------------------------------------------------------------------------------------
// BitcoinBurnTxID mapping functions
// <BitcoinBurnTxID BlockHash> -> <>
// -------------------------------------------------------------------------------------

func _keyForBitcoinBurnTxID(bitcoinBurnTxID *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same
	// underlying array.
	prefixCopy := append([]byte{}, Prefixes.PrefixBitcoinBurnTxIDs...)
	return append(prefixCopy, bitcoinBurnTxID[:]...)
}

func DbPutBitcoinBurnTxIDWithTxn(txn *badger.Txn, snap *Snapshot, bitcoinBurnTxID *BlockHash) error {
	return DBSetWithTxn(txn, snap, _keyForBitcoinBurnTxID(bitcoinBurnTxID), []byte{})
}

func DbExistsBitcoinBurnTxIDWithTxn(txn *badger.Txn, snap *Snapshot, bitcoinBurnTxID *BlockHash) bool {
	// We don't care about the value because we're just checking to see if the key exists.
	if _, err := DBGetWithTxn(txn, snap, _keyForBitcoinBurnTxID(bitcoinBurnTxID)); err != nil {
		return false
	}
	return true
}

func DbExistsBitcoinBurnTxID(db *badger.DB, snap *Snapshot, bitcoinBurnTxID *BlockHash) bool {
	var exists bool
	db.View(func(txn *badger.Txn) error {
		exists = DbExistsBitcoinBurnTxIDWithTxn(txn, snap, bitcoinBurnTxID)
		return nil
	})
	return exists
}

func DbDeleteBitcoinBurnTxIDWithTxn(txn *badger.Txn, snap *Snapshot, bitcoinBurnTxID *BlockHash) error {
	return DBDeleteWithTxn(txn, snap, _keyForBitcoinBurnTxID(bitcoinBurnTxID))
}

func DbGetAllBitcoinBurnTxIDs(handle *badger.DB) (_bitcoinBurnTxIDs []*BlockHash) {
	keysFound, _ := _enumerateKeysForPrefix(handle, Prefixes.PrefixBitcoinBurnTxIDs)
	bitcoinBurnTxIDs := []*BlockHash{}
	for _, key := range keysFound {
		bbtxid := &BlockHash{}
		copy(bbtxid[:], key[1:])
		bitcoinBurnTxIDs = append(bitcoinBurnTxIDs, bbtxid)
	}

	return bitcoinBurnTxIDs
}

func _getBlockHashForPrefixWithTxn(txn *badger.Txn, snap *Snapshot, prefix []byte) *BlockHash {
	blockHash, err := DBGetWithTxn(txn, snap, prefix)
	if err != nil {
		return nil
	}

	return NewBlockHash(blockHash)
}

func _getBlockHashForPrefix(handle *badger.DB, snap *Snapshot, prefix []byte) *BlockHash {
	var ret *BlockHash
	err := handle.View(func(txn *badger.Txn) error {
		ret = _getBlockHashForPrefixWithTxn(txn, snap, prefix)
		return nil
	})
	if err != nil {
		return nil
	}
	return ret
}

// GetBadgerDbPath returns the path where we store the badgerdb data.
func GetBadgerDbPath(dataDir string) string {
	return filepath.Join(dataDir, BadgerDbFolder)
}

func _EncodeUint32(num uint32) []byte {
	numBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(numBytes, num)
	return numBytes
}

func DecodeUint32(num []byte) uint32 {
	return binary.BigEndian.Uint32(num)
}

func EncodeUint64(num uint64) []byte {
	numBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(numBytes, num)
	return numBytes
}

func DecodeUint64(scoreBytes []byte) uint64 {
	return binary.BigEndian.Uint64(scoreBytes)
}

func DbPutNanosPurchasedWithTxn(txn *badger.Txn, snap *Snapshot, nanosPurchased uint64) error {
	return DBSetWithTxn(txn, snap, Prefixes.PrefixNanosPurchased, EncodeUint64(nanosPurchased))
}

func DbPutNanosPurchased(handle *badger.DB, snap *Snapshot, nanosPurchased uint64) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbPutNanosPurchasedWithTxn(txn, snap, nanosPurchased)
	})
}

func DbGetNanosPurchasedWithTxn(txn *badger.Txn, snap *Snapshot) uint64 {
	nanosPurchasedBytes, err := DBGetWithTxn(txn, snap, Prefixes.PrefixNanosPurchased)
	if err != nil {
		return 0
	}

	return DecodeUint64(nanosPurchasedBytes)
}

func DbGetNanosPurchased(handle *badger.DB, snap *Snapshot) uint64 {
	var nanosPurchased uint64
	handle.View(func(txn *badger.Txn) error {
		nanosPurchased = DbGetNanosPurchasedWithTxn(txn, snap)
		return nil
	})

	return nanosPurchased
}

func DbPutGlobalParamsEntry(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	globalParamsEntry GlobalParamsEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutGlobalParamsEntryWithTxn(txn, snap, blockHeight, globalParamsEntry)
	})
}

func DbPutGlobalParamsEntryWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	globalParamsEntry GlobalParamsEntry) error {

	err := DBSetWithTxn(txn, snap, Prefixes.PrefixGlobalParams, EncodeToBytes(blockHeight, &globalParamsEntry))
	if err != nil {
		return errors.Wrapf(err, "DbPutGlobalParamsEntryWithTxn: Problem adding global params entry to db: ")
	}
	return nil
}

func DbGetGlobalParamsEntryWithTxn(txn *badger.Txn, snap *Snapshot) *GlobalParamsEntry {
	globalParamsEntryBytes, err := DBGetWithTxn(txn, snap, Prefixes.PrefixGlobalParams)
	if err != nil {
		return &InitialGlobalParamsEntry
	}
	globalParamsEntryObj := &GlobalParamsEntry{}
	rr := bytes.NewReader(globalParamsEntryBytes)
	DecodeFromBytes(globalParamsEntryObj, rr)

	return globalParamsEntryObj
}

func DbGetGlobalParamsEntry(handle *badger.DB, snap *Snapshot) *GlobalParamsEntry {
	var globalParamsEntry *GlobalParamsEntry
	handle.View(func(txn *badger.Txn) error {
		globalParamsEntry = DbGetGlobalParamsEntryWithTxn(txn, snap)
		return nil
	})
	return globalParamsEntry
}

func DbPutUSDCentsPerBitcoinExchangeRateWithTxn(txn *badger.Txn, snap *Snapshot,
	usdCentsPerBitcoinExchangeRate uint64) error {

	return DBSetWithTxn(txn, snap, Prefixes.PrefixUSDCentsPerBitcoinExchangeRate,
		EncodeUint64(usdCentsPerBitcoinExchangeRate))
}

func DbGetUSDCentsPerBitcoinExchangeRateWithTxn(txn *badger.Txn, snap *Snapshot) uint64 {
	usdCentsPerBitcoinExchangeRateBytes, err := DBGetWithTxn(txn, snap, Prefixes.PrefixUSDCentsPerBitcoinExchangeRate)
	if err != nil {
		return InitialUSDCentsPerBitcoinExchangeRate
	}

	return DecodeUint64(usdCentsPerBitcoinExchangeRateBytes)
}

func DbGetUSDCentsPerBitcoinExchangeRate(handle *badger.DB, snap *Snapshot) uint64 {
	var usdCentsPerBitcoinExchangeRate uint64
	handle.View(func(txn *badger.Txn) error {
		usdCentsPerBitcoinExchangeRate = DbGetUSDCentsPerBitcoinExchangeRateWithTxn(txn, snap)
		return nil
	})

	return usdCentsPerBitcoinExchangeRate
}

func GetUtxoNumEntriesWithTxn(txn *badger.Txn, snap *Snapshot) uint64 {
	indexBytes, err := DBGetWithTxn(txn, snap, Prefixes.PrefixUtxoNumEntries)
	if err != nil {
		return 0
	}

	return DecodeUint64(indexBytes)
}

func GetUtxoNumEntries(handle *badger.DB, snap *Snapshot) uint64 {
	var numEntries uint64
	handle.View(func(txn *badger.Txn) error {
		numEntries = GetUtxoNumEntriesWithTxn(txn, snap)
		return nil
	})

	return numEntries
}

func _SerializeUtxoKey(utxoKey *UtxoKey) []byte {
	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, utxoKey.Index)
	return append(utxoKey.TxID[:], indexBytes...)

}

func _DbKeyForUtxoKey(utxoKey *UtxoKey) []byte {
	return append(append([]byte{}, Prefixes.PrefixUtxoKeyToUtxoEntry...), _SerializeUtxoKey(utxoKey)...)
}

// Implements the reverse of _DbKeyForUtxoKey. This doesn't error-check
// and caller should make sure they're passing a properly-sized key to
// this function.
func _UtxoKeyFromDbKey(utxoDbKey []byte) *UtxoKey {
	// Read in the TxID, which is at the beginning.
	txIDBytes := utxoDbKey[:HashSizeBytes]
	txID := BlockHash{}
	copy(txID[:], txIDBytes)
	// Read in the index, which is encoded as a bigint at the end.
	indexBytes := utxoDbKey[HashSizeBytes:]
	indexValue := binary.BigEndian.Uint32(indexBytes)
	return &UtxoKey{
		Index: indexValue,
		TxID:  txID,
	}
}

func PutUtxoNumEntriesWithTxn(txn *badger.Txn, snap *Snapshot, newNumEntries uint64) error {
	return DBSetWithTxn(txn, snap, Prefixes.PrefixUtxoNumEntries, EncodeUint64(newNumEntries))
}

func PutUtxoEntryForUtxoKeyWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	utxoKey *UtxoKey, utxoEntry *UtxoEntry) error {

	return DBSetWithTxn(txn, snap, _DbKeyForUtxoKey(utxoKey), EncodeToBytes(blockHeight, utxoEntry))
}

func DbGetUtxoEntryForUtxoKeyWithTxn(txn *badger.Txn, snap *Snapshot, utxoKey *UtxoKey) *UtxoEntry {
	utxoDbKey := _DbKeyForUtxoKey(utxoKey)
	utxoEntryBytes, err := DBGetWithTxn(txn, snap, utxoDbKey)
	if err != nil {
		return nil
	}

	utxoEntry := &UtxoEntry{}
	rr := bytes.NewReader(utxoEntryBytes)
	DecodeFromBytes(utxoEntry, rr)
	return utxoEntry
}

func DbGetUtxoEntryForUtxoKey(handle *badger.DB, snap *Snapshot, utxoKey *UtxoKey) *UtxoEntry {
	var ret *UtxoEntry
	handle.View(func(txn *badger.Txn) error {
		ret = DbGetUtxoEntryForUtxoKeyWithTxn(txn, snap, utxoKey)
		return nil
	})

	return ret
}

func DeleteUtxoEntryForKeyWithTxn(txn *badger.Txn, snap *Snapshot, utxoKey *UtxoKey) error {
	return DBDeleteWithTxn(txn, snap, _DbKeyForUtxoKey(utxoKey))
}

func DeletePubKeyUtxoKeyMappingWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, utxoKey *UtxoKey) error {
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("DeletePubKeyUtxoKeyMappingWithTxn: Public key has improper length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}

	keyToDelete := append(append([]byte{}, Prefixes.PrefixPubKeyUtxoKey...), publicKey...)
	keyToDelete = append(keyToDelete, _SerializeUtxoKey(utxoKey)...)

	return DBDeleteWithTxn(txn, snap, keyToDelete)
}

func PutPubKeyUtxoKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte, utxoKey *UtxoKey) error {
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("PutPubKeyUtxoKeyWithTxn: Public key has improper length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}

	keyToAdd := append(append([]byte{}, Prefixes.PrefixPubKeyUtxoKey...), publicKey...)
	keyToAdd = append(keyToAdd, _SerializeUtxoKey(utxoKey)...)

	return DBSetWithTxn(txn, snap, keyToAdd, []byte{})
}

// DbGetUtxosForPubKey finds the UtxoEntry's corresponding to the public
// key passed in. It also attaches the UtxoKeys to the UtxoEntry's it
// returns for easy access.
func DbGetUtxosForPubKey(publicKey []byte, handle *badger.DB, snap *Snapshot) ([]*UtxoEntry, error) {
	// Verify the length of the public key.
	if len(publicKey) != btcec.PubKeyBytesLenCompressed {
		return nil, fmt.Errorf("DbGetUtxosForPubKey: Public key has improper "+
			"length %d != %d", len(publicKey), btcec.PubKeyBytesLenCompressed)
	}
	// Look up the utxo keys for this public key.
	utxoEntriesFound := []*UtxoEntry{}
	err := handle.View(func(txn *badger.Txn) error {
		// Start by looping through to find all the UtxoKeys.
		utxoKeysFound := []*UtxoKey{}
		opts := badger.DefaultIteratorOptions
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()
		prefix := append(append([]byte{}, Prefixes.PrefixPubKeyUtxoKey...), publicKey...)
		for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			// Strip the prefix off the key. What's left should be the UtxoKey.
			pkUtxoKey := nodeIterator.Item().Key()
			utxoKeyBytes := pkUtxoKey[len(prefix):]
			// The size of the utxo key bytes should be equal to the size of a
			// standard hash (the txid) plus the size of a uint32.
			if len(utxoKeyBytes) != HashSizeBytes+4 {
				return fmt.Errorf("Problem reading <pk, utxoKey> mapping; key size %d "+
					"is not equal to (prefix_byte=%d + len(publicKey)=%d + len(utxoKey)=%d)=%d. "+
					"Key found: %#v", len(pkUtxoKey), len(Prefixes.PrefixPubKeyUtxoKey), len(publicKey), HashSizeBytes+4, len(prefix)+HashSizeBytes+4, pkUtxoKey)
			}
			// Try and convert the utxo key bytes into a utxo key.
			utxoKey := _UtxoKeyFromDbKey(utxoKeyBytes)
			if utxoKey == nil {
				return fmt.Errorf("Problem reading <pk, utxoKey> mapping; parsing UtxoKey bytes %#v returned nil", utxoKeyBytes)
			}

			// Now that we have the utxoKey, enqueue it.
			utxoKeysFound = append(utxoKeysFound, utxoKey)
		}

		// Once all the UtxoKeys are found, fetch all the UtxoEntries.
		for ii := range utxoKeysFound {
			foundUtxoKey := utxoKeysFound[ii]
			utxoEntry := DbGetUtxoEntryForUtxoKeyWithTxn(txn, snap, foundUtxoKey)
			if utxoEntry == nil {
				return fmt.Errorf("UtxoEntry for UtxoKey %v was not found", foundUtxoKey)
			}

			// Set a back-reference to the utxo key.
			utxoEntry.UtxoKey = foundUtxoKey

			utxoEntriesFound = append(utxoEntriesFound, utxoEntry)
		}

		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "DbGetUtxosForPubKey: ")
	}

	// If there are no errors, return everything we found.
	return utxoEntriesFound, nil
}

func DeleteUnmodifiedMappingsForUtxoWithTxn(txn *badger.Txn, snap *Snapshot, utxoKey *UtxoKey) error {
	// Get the entry for the utxoKey from the db.
	utxoEntry := DbGetUtxoEntryForUtxoKeyWithTxn(txn, snap, utxoKey)
	if utxoEntry == nil {
		// If an entry doesn't exist for this key then there is nothing in the
		// db to delete.
		return nil
	}

	// If the entry exists, delete the <UtxoKey -> UtxoEntry> mapping from the db.
	// It is assumed that the entry corresponding to a key has not been modified
	// and so is OK to delete
	if err := DeleteUtxoEntryForKeyWithTxn(txn, snap, utxoKey); err != nil {
		return err
	}

	// Delete the <pubkey, utxoKey> -> <> mapping.
	if err := DeletePubKeyUtxoKeyMappingWithTxn(txn, snap, utxoEntry.PublicKey, utxoKey); err != nil {
		return err
	}

	return nil
}

func PutMappingsForUtxoWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	utxoKey *UtxoKey, utxoEntry *UtxoEntry) error {
	// Put the <utxoKey -> utxoEntry> mapping.
	if err := PutUtxoEntryForUtxoKeyWithTxn(txn, snap, blockHeight, utxoKey, utxoEntry); err != nil {
		return nil
	}

	// Put the <pubkey, utxoKey> -> <> mapping.
	if err := PutPubKeyUtxoKeyWithTxn(txn, snap, utxoEntry.PublicKey, utxoKey); err != nil {
		return err
	}

	return nil
}

func _DbKeyForUtxoOps(blockHash *BlockHash) []byte {
	return append(append([]byte{}, Prefixes.PrefixBlockHashToUtxoOperations...), blockHash[:]...)
}

func GetUtxoOperationsForBlockWithTxn(txn *badger.Txn, snap *Snapshot, blockHash *BlockHash) ([][]*UtxoOperation, error) {
	utxoOpsBytes, err := DBGetWithTxn(txn, snap, _DbKeyForUtxoOps(blockHash))
	if err != nil {
		return nil, err
	}

	utxoOpsBundle := &UtxoOperationBundle{}
	rr := bytes.NewReader(utxoOpsBytes)
	if exists, err := DecodeFromBytes(utxoOpsBundle, rr); !exists || err != nil {
		return nil, errors.Wrapf(err, "GetUtxoOperationsForBlockWithTxn: Problem decoding utxoOpsBundle")
	}

	return utxoOpsBundle.UtxoOpBundle, nil
}

func GetUtxoOperationsForBlock(handle *badger.DB, snap *Snapshot, blockHash *BlockHash) ([][]*UtxoOperation, error) {
	var ops [][]*UtxoOperation
	err := handle.View(func(txn *badger.Txn) error {
		var err error
		ops, err = GetUtxoOperationsForBlockWithTxn(txn, snap, blockHash)
		return err
	})

	return ops, err
}

func PutUtxoOperationsForBlockWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	blockHash *BlockHash, utxoOpsForBlock [][]*UtxoOperation) error {

	opBundle := &UtxoOperationBundle{
		UtxoOpBundle: utxoOpsForBlock,
	}
	return DBSetWithTxn(txn, snap, _DbKeyForUtxoOps(blockHash), EncodeToBytes(blockHeight, opBundle))
}

func DeleteUtxoOperationsForBlockWithTxn(txn *badger.Txn, snap *Snapshot, blockHash *BlockHash) error {
	return DBDeleteWithTxn(txn, snap, _DbKeyForUtxoOps(blockHash))
}

func SerializeBlockNode(blockNode *BlockNode) ([]byte, error) {
	data := []byte{}

	// Hash
	if blockNode.Hash == nil {
		return nil, fmt.Errorf("SerializeBlockNode: Hash cannot be nil")
	}
	data = append(data, blockNode.Hash[:]...)

	// Height
	data = append(data, UintToBuf(uint64(blockNode.Height))...)

	// DifficultyTarget
	if blockNode.DifficultyTarget == nil {
		return nil, fmt.Errorf("SerializeBlockNode: DifficultyTarget cannot be nil")
	}
	data = append(data, blockNode.DifficultyTarget[:]...)

	// CumWork
	data = append(data, BigintToHash(blockNode.CumWork)[:]...)

	// Header
	serializedHeader, err := blockNode.Header.ToBytes(false)
	if err != nil {
		return nil, errors.Wrapf(err, "SerializeBlockNode: Problem serializing header")
	}
	data = append(data, IntToBuf(int64(len(serializedHeader)))...)
	data = append(data, serializedHeader...)

	// Status
	// It's assumed this field is one byte long.
	data = append(data, UintToBuf(uint64(blockNode.Status))...)

	return data, nil
}

func DeserializeBlockNode(data []byte) (*BlockNode, error) {
	blockNode := NewBlockNode(
		nil,          // Parent
		&BlockHash{}, // Hash
		0,            // Height
		&BlockHash{}, // DifficultyTarget
		nil,          // CumWork
		nil,          // Header
		StatusNone,   // Status

	)

	rr := bytes.NewReader(data)

	// Hash
	_, err := io.ReadFull(rr, blockNode.Hash[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Hash")
	}

	// Height
	height, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Height")
	}
	blockNode.Height = uint32(height)

	// DifficultyTarget
	_, err = io.ReadFull(rr, blockNode.DifficultyTarget[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding DifficultyTarget")
	}

	// CumWork
	tmp := BlockHash{}
	_, err = io.ReadFull(rr, tmp[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding CumWork")
	}
	blockNode.CumWork = HashToBigint(&tmp)

	// Header
	payloadLen, err := ReadVarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Header length")
	}
	headerBytes := make([]byte, payloadLen)
	_, err = io.ReadFull(rr, headerBytes[:])
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem reading Header bytes")
	}
	blockNode.Header = NewMessage(MsgTypeHeader).(*MsgDeSoHeader)
	err = blockNode.Header.FromBytes(headerBytes)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem parsing Header bytes")
	}

	// Status
	status, err := ReadUvarint(rr)
	if err != nil {
		return nil, errors.Wrapf(err, "DeserializeBlockNode: Problem decoding Status")
	}
	blockNode.Status = BlockStatus(uint32(status))

	return blockNode, nil
}

type ChainType uint8

const (
	ChainTypeDeSoBlock = iota
	ChainTypeBitcoinHeader
)

func _prefixForChainType(chainType ChainType) []byte {
	var prefix []byte
	switch chainType {
	case ChainTypeDeSoBlock:
		prefix = Prefixes.PrefixBestDeSoBlockHash
	case ChainTypeBitcoinHeader:
		prefix = Prefixes.PrefixBestBitcoinHeaderHash
	default:
		glog.Errorf("_prefixForChainType: Unknown ChainType %d; this should never happen", chainType)
		return nil
	}

	return prefix
}

func DbGetBestHash(handle *badger.DB, snap *Snapshot, chainType ChainType) *BlockHash {
	prefix := _prefixForChainType(chainType)
	if len(prefix) == 0 {
		glog.Errorf("DbGetBestHash: Problem getting prefix for ChainType: %d", chainType)
		return nil
	}
	return _getBlockHashForPrefix(handle, snap, prefix)
}

func PutBestHashWithTxn(txn *badger.Txn, snap *Snapshot,
	bh *BlockHash, chainType ChainType) error {

	prefix := _prefixForChainType(chainType)
	if len(prefix) == 0 {
		glog.Errorf("PutBestHashWithTxn: Problem getting prefix for ChainType: %d", chainType)
		return nil
	}
	return DBSetWithTxn(txn, snap, prefix, bh[:])
}

func PutBestHash(handle *badger.DB, snap *Snapshot, bh *BlockHash, chainType ChainType) error {
	return handle.Update(func(txn *badger.Txn) error {
		return PutBestHashWithTxn(txn, snap, bh, chainType)
	})
}

func BlockHashToBlockKey(blockHash *BlockHash) []byte {
	return append(append([]byte{}, Prefixes.PrefixBlockHashToBlock...), blockHash[:]...)
}

func PublicKeyBlockHashToBlockRewardKey(publicKey []byte, blockHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPublicKeyBlockHashToBlockReward...)
	key := append(prefixCopy, publicKey...)
	key = append(key, blockHash[:]...)
	return key
}

func GetBlockWithTxn(txn *badger.Txn, snap *Snapshot, blockHash *BlockHash) *MsgDeSoBlock {
	hashKey := BlockHashToBlockKey(blockHash)

	blockBytes, err := DBGetWithTxn(txn, snap, hashKey)
	if err != nil {
		return nil
	}

	blockRet := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	if err := blockRet.FromBytes(blockBytes); err != nil {
		return nil
	}

	return blockRet
}

func GetBlock(blockHash *BlockHash, handle *badger.DB, snap *Snapshot) (*MsgDeSoBlock, error) {
	hashKey := BlockHashToBlockKey(blockHash)
	var blockRet *MsgDeSoBlock
	err := handle.View(func(txn *badger.Txn) error {
		blockBytes, err := DBGetWithTxn(txn, snap, hashKey)
		if err != nil {
			return err
		}

		ret := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
		if err := ret.FromBytes(blockBytes); err != nil {
			return err
		}
		blockRet = ret
		return nil
	})
	if err != nil {
		return nil, err
	}

	return blockRet, nil
}

func PutBlockWithTxn(txn *badger.Txn, snap *Snapshot, desoBlock *MsgDeSoBlock) error {
	if desoBlock.Header == nil {
		return fmt.Errorf("PutBlockWithTxn: Header was nil in block %v", desoBlock)
	}
	blockHash, err := desoBlock.Header.Hash()
	if err != nil {
		return errors.Wrapf(err, "PutBlockWithTxn: Problem hashing header: ")
	}
	blockKey := BlockHashToBlockKey(blockHash)
	data, err := desoBlock.ToBytes(false)
	if err != nil {
		return err
	}
	// First check to see if the block is already in the db.
	if _, err := DBGetWithTxn(txn, snap, blockKey); err == nil {
		// err == nil means the block already exists in the db so
		// no need to store it.
		return nil
	}
	// If the block is not in the db then set it.
	if err := DBSetWithTxn(txn, snap, blockKey, data); err != nil {
		return err
	}

	// Index the block reward. Used for deducting immature block rewards from user balances.
	if len(desoBlock.Txns) == 0 {
		return fmt.Errorf("PutBlockWithTxn: Got block without any txns %v", desoBlock)
	}
	blockRewardTxn := desoBlock.Txns[0]
	if blockRewardTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return fmt.Errorf("PutBlockWithTxn: Got block without block reward as first txn %v", desoBlock)
	}
	// It's possible the block reward is split across multiple public keys.
	pubKeyToBlockRewardMap := make(map[PkMapKey]uint64)
	for _, bro := range desoBlock.Txns[0].TxOutputs {
		pkMapKey := MakePkMapKey(bro.PublicKey)
		if _, hasKey := pubKeyToBlockRewardMap[pkMapKey]; !hasKey {
			pubKeyToBlockRewardMap[pkMapKey] = bro.AmountNanos
		} else {
			pubKeyToBlockRewardMap[pkMapKey] += bro.AmountNanos
		}
	}
	for pkMapKeyIter, blockReward := range pubKeyToBlockRewardMap {
		pkMapKey := pkMapKeyIter

		blockRewardKey := PublicKeyBlockHashToBlockRewardKey(pkMapKey[:], blockHash)
		if err := DBSetWithTxn(txn, snap, blockRewardKey, EncodeUint64(blockReward)); err != nil {
			return err
		}
	}

	return nil
}

func PutBlock(handle *badger.DB, snap *Snapshot, desoBlock *MsgDeSoBlock) error {
	err := handle.Update(func(txn *badger.Txn) error {
		return PutBlockWithTxn(txn, snap, desoBlock)
	})
	if err != nil {
		return err
	}

	return nil
}

func DeleteBlockReward(handle *badger.DB, snap *Snapshot, desoBlock *MsgDeSoBlock) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DeleteBlockRewardWithTxn(txn, snap, desoBlock)
	})
}

func DeleteBlockRewardWithTxn(txn *badger.Txn, snap *Snapshot, desoBlock *MsgDeSoBlock) error {
	blockHash, err := desoBlock.Header.Hash()
	if err != nil {
		return errors.Wrapf(err, "DeleteBlockRewardWithTxn: Problem hashing header: ")
	}

	// Index the block reward. Used for deducting immature block rewards from user balances.
	if len(desoBlock.Txns) == 0 {
		return fmt.Errorf("DeleteBlockRewardWithTxn: Got block without any txns %v", desoBlock)
	}
	blockRewardTxn := desoBlock.Txns[0]
	if blockRewardTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
		return fmt.Errorf("DeleteBlockRewardWithTxn: Got block without block reward as first txn %v", desoBlock)
	}
	// It's possible the block reward is split across multiple public keys.
	blockRewardPublicKeys := make(map[PkMapKey]bool)
	for _, bro := range desoBlock.Txns[0].TxOutputs {
		pkMapKey := MakePkMapKey(bro.PublicKey)
		blockRewardPublicKeys[pkMapKey] = true
	}
	for pkMapKeyIter := range blockRewardPublicKeys {
		pkMapKey := pkMapKeyIter

		blockRewardKey := PublicKeyBlockHashToBlockRewardKey(pkMapKey[:], blockHash)
		if err := DBDeleteWithTxn(txn, snap, blockRewardKey); err != nil {
			return err
		}
	}

	return nil
}

func DbGetBlockRewardForPublicKeyBlockHashWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte, blockHash *BlockHash,
) (_balance uint64, _err error) {
	key := PublicKeyBlockHashToBlockRewardKey(publicKey, blockHash)
	desoBalanceBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return uint64(0), nil
	}
	return DecodeUint64(desoBalanceBytes), nil
}

func DbGetBlockRewardForPublicKeyBlockHash(db *badger.DB, snap *Snapshot, publicKey []byte, blockHash *BlockHash,
) (_balance uint64, _err error) {
	ret := uint64(0)
	dbErr := db.View(func(txn *badger.Txn) error {
		var err error
		ret, err = DbGetBlockRewardForPublicKeyBlockHashWithTxn(txn, snap, publicKey, blockHash)
		if err != nil {
			return errors.Wrap(err, "DbGetBlockRewardForPublicKeyBlockHash: ")
		}
		return nil
	})
	if dbErr != nil {
		return uint64(0), dbErr
	}
	return ret, nil
}

func _heightHashToNodeIndexPrefix(bitcoinNodes bool) []byte {
	prefix := append([]byte{}, Prefixes.PrefixHeightHashToNodeInfo...)
	if bitcoinNodes {
		prefix = append([]byte{}, Prefixes.PrefixBitcoinHeightHashToNodeInfo...)
	}

	return prefix
}

func _heightHashToNodeIndexKey(height uint32, hash *BlockHash, bitcoinNodes bool) []byte {
	prefix := _heightHashToNodeIndexPrefix(bitcoinNodes)

	heightBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(heightBytes[:], height)
	key := append(prefix, heightBytes[:]...)
	key = append(key, hash[:]...)

	return key
}

func GetHeightHashToNodeInfoWithTxn(txn *badger.Txn, snap *Snapshot,
	height uint32, hash *BlockHash, bitcoinNodes bool) *BlockNode {

	key := _heightHashToNodeIndexKey(height, hash, bitcoinNodes)
	nodeBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	var blockNode *BlockNode
	blockNode, err = DeserializeBlockNode(nodeBytes)
	if err != nil {
		return nil
	}
	return blockNode
}

func GetHeightHashToNodeInfo(handle *badger.DB, snap *Snapshot,
	height uint32, hash *BlockHash, bitcoinNodes bool) *BlockNode {

	var blockNode *BlockNode
	handle.View(func(txn *badger.Txn) error {
		blockNode = GetHeightHashToNodeInfoWithTxn(txn, snap, height, hash, bitcoinNodes)
		return nil
	})
	return blockNode
}

func PutHeightHashToNodeInfoWithTxn(txn *badger.Txn, snap *Snapshot,
	node *BlockNode, bitcoinNodes bool) error {

	key := _heightHashToNodeIndexKey(node.Height, node.Hash, bitcoinNodes)
	serializedNode, err := SerializeBlockNode(node)
	if err != nil {
		return errors.Wrapf(err, "PutHeightHashToNodeInfoWithTxn: Problem serializing node")
	}

	if err := DBSetWithTxn(txn, snap, key, serializedNode); err != nil {
		return err
	}
	return nil
}

func PutHeightHashToNodeInfo(handle *badger.DB, snap *Snapshot, node *BlockNode, bitcoinNodes bool) error {
	err := handle.Update(func(txn *badger.Txn) error {
		return PutHeightHashToNodeInfoWithTxn(txn, snap, node, bitcoinNodes)
	})

	if err != nil {
		return err
	}

	return nil
}

func DbDeleteHeightHashToNodeInfoWithTxn(txn *badger.Txn, snap *Snapshot,
	node *BlockNode, bitcoinNodes bool) error {

	return DBDeleteWithTxn(txn, snap, _heightHashToNodeIndexKey(node.Height, node.Hash, bitcoinNodes))
}

func DbBulkDeleteHeightHashToNodeInfo(handle *badger.DB, snap *Snapshot,
	nodes []*BlockNode, bitcoinNodes bool) error {

	err := handle.Update(func(txn *badger.Txn) error {
		for _, nn := range nodes {
			if err := DbDeleteHeightHashToNodeInfoWithTxn(txn, snap, nn, bitcoinNodes); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

// InitDbWithGenesisBlock initializes the database to contain only the genesis
// block.
func InitDbWithDeSoGenesisBlock(params *DeSoParams, handle *badger.DB,
	eventManager *EventManager, snap *Snapshot) error {
	// Construct a node for the genesis block. Its height is zero and it has
	// no parents. Its difficulty should be set to the initial
	// difficulty specified in the parameters and it should be assumed to be
	// valid and stored by the end of this function.
	genesisBlock := params.GenesisBlock
	diffTarget := MustDecodeHexBlockHash(params.MinDifficultyTargetHex)
	blockHash := MustDecodeHexBlockHash(params.GenesisBlockHashHex)
	genesisNode := NewBlockNode(
		nil, // Parent
		blockHash,
		0, // Height
		diffTarget,
		BytesToBigint(ExpectedWorkForBlockHash(diffTarget)[:]), // CumWork
		genesisBlock.Header, // Header
		StatusHeaderValidated|StatusBlockProcessed|StatusBlockStored|StatusBlockValidated, // Status
	)

	// Set the fields in the db to reflect the current state of our chain.
	//
	// Set the best hash to the genesis block in the db since its the only node
	// we're currently aware of. Set it for both the header chain and the block
	// chain.
	if snap != nil {
		snap.PrepareAncestralRecordsFlush()
	}

	if err := PutBestHash(handle, snap, blockHash, ChainTypeDeSoBlock); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting genesis block hash into db for block chain")
	}
	// Add the genesis block to the (hash -> block) index.
	if err := PutBlock(handle, snap, genesisBlock); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting genesis block into db")
	}
	// Add the genesis block to the (height, hash -> node info) index in the db.
	if err := PutHeightHashToNodeInfo(handle, snap, genesisNode, false /*bitcoinNodes*/); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting (height, hash -> node) in db")
	}
	if err := DbPutNanosPurchased(handle, snap, params.DeSoNanosPurchasedAtGenesis); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting genesis block hash into db for block chain")
	}
	if err := DbPutGlobalParamsEntry(handle, snap, 0, InitialGlobalParamsEntry); err != nil {
		return errors.Wrapf(err, "InitDbWithGenesisBlock: Problem putting GlobalParamsEntry into db for block chain")
	}

	if snap != nil {
		snap.StartAncestralRecordsFlush(true)
	}

	// We apply seed transactions here. This step is useful for setting
	// up the blockchain with a particular set of transactions, e.g. when
	// hard forking the chain.
	//
	// TODO: Right now there's an issue where if we hit an error during this
	// step of the initialization, the next time we run the program it will
	// think things are initialized because we set the best block hash at the
	// top. We should fix this at some point so that an error in this step
	// wipes out the best hash.
	utxoView, err := NewUtxoView(handle, params, nil, snap)
	if err != nil {
		return fmt.Errorf(
			"InitDbWithDeSoGenesisBlock: Error initializing UtxoView")
	}

	// Add the seed balances to the view.
	for index, txOutput := range params.SeedBalances {
		outputKey := UtxoKey{
			TxID:  BlockHash{},
			Index: uint32(index),
		}
		utxoEntry := UtxoEntry{
			AmountNanos: txOutput.AmountNanos,
			PublicKey:   txOutput.PublicKey,
			BlockHeight: 0,
			// Just make this a normal transaction so that we don't have to wait for
			// the block reward maturity.
			UtxoType: UtxoTypeOutput,
			UtxoKey:  &outputKey,
		}

		_, err := utxoView._addUtxo(&utxoEntry)
		if err != nil {
			return fmt.Errorf("InitDbWithDeSoGenesisBlock: Error adding "+
				"seed balance at index %v ; output: %v: %v", index, txOutput, err)
		}
	}

	// Add the seed txns to the view
	utxoOpsForBlock := [][]*UtxoOperation{}
	for txnIndex, txnHex := range params.SeedTxns {
		txnBytes, err := hex.DecodeString(txnHex)
		if err != nil {
			return fmt.Errorf(
				"InitDbWithDeSoGenesisBlock: Error decoding seed "+
					"txn HEX: %v, txn index: %v, txn hex: %v",
				err, txnIndex, txnHex)
		}
		txn := &MsgDeSoTxn{}
		if err := txn.FromBytes(txnBytes); err != nil {
			return fmt.Errorf(
				"InitDbWithDeSoGenesisBlock: Error decoding seed "+
					"txn BYTES: %v, txn index: %v, txn hex: %v",
				err, txnIndex, txnHex)
		}
		// Important: ignoreUtxos makes it so that the inputs/outputs aren't
		// processed, which is important.
		// Set txnSizeBytes to 0 here as the minimum network fee is 0 at genesis block, so there is no need to serialize
		// these transactions to check if they meet the minimum network fee requirement.
		var utxoOpsForTxn []*UtxoOperation
		utxoOpsForTxn, _, _, _, err = utxoView.ConnectTransaction(
			txn, txn.Hash(), 0, 0 /*blockHeight*/, false /*verifySignatures*/, true /*ignoreUtxos*/)
		if err != nil {
			return fmt.Errorf(
				"InitDbWithDeSoGenesisBlock: Error connecting transaction: %v, "+
					"txn index: %v, txn hex: %v",
				err, txnIndex, txnHex)
		}
		utxoOpsForBlock = append(utxoOpsForBlock, utxoOpsForTxn)
	}

	// If we have an event manager, initialize the genesis block with the current
	// state of the view.
	if eventManager != nil {
		eventManager.blockConnected(&BlockEvent{
			Block:    genesisBlock,
			UtxoView: utxoView,
			UtxoOps:  utxoOpsForBlock,
		})
	}

	// Flush all the data in the view.
	err = utxoView.FlushToDb(0)
	if err != nil {
		return fmt.Errorf(
			"InitDbWithDeSoGenesisBlock: Error flushing seed txns to DB: %v", err)
	}

	return nil
}

// GetBlockTipHeight fetches the current block tip height from the database.
func GetBlockTipHeight(handle *badger.DB, bitcoinNodes bool) (uint64, error) {
	var blockHeight uint64
	prefix := _heightHashToNodeIndexPrefix(bitcoinNodes)
	// Seek prefix will look for the block node with the largest block height. We populate the maximal possible
	// uint32 and iterate backwards.
	seekPrefix := append(prefix, []byte{0xff, 0xff, 0xff, 0xff}...)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Reverse = true
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()

		// Fetch a single blocknode and then return.
		nodeIterator.Seek(seekPrefix)
		if !nodeIterator.ValidForPrefix(prefix) {
			return fmt.Errorf("No block nodes were found in the database")
		}

		item := nodeIterator.Item()
		err := item.Value(func(blockNodeBytes []byte) error {
			blockNode, err := DeserializeBlockNode(blockNodeBytes)
			if err != nil {
				return err
			}
			blockHeight = uint64(blockNode.Height)
			return nil
		})
		return err
	})
	return blockHeight, err
}

func GetBlockIndex(handle *badger.DB, bitcoinNodes bool) (map[BlockHash]*BlockNode, error) {
	blockIndex := make(map[BlockHash]*BlockNode)

	prefix := _heightHashToNodeIndexPrefix(bitcoinNodes)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()
		for nodeIterator.Seek(prefix); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			var blockNode *BlockNode

			// Don't bother checking the key. We assume that the key lines up
			// with what we've stored in the value in terms of (height, block hash).
			item := nodeIterator.Item()
			err := item.Value(func(blockNodeBytes []byte) error {
				// Deserialize the block node.
				var err error
				// TODO: There is room for optimization here by pre-allocating a
				// contiguous list of block nodes and then populating that list
				// rather than having each blockNode be a stand-alone allocation.
				blockNode, err = DeserializeBlockNode(blockNodeBytes)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}

			// If we got here it means we read a blockNode successfully. Store it
			// into our node index.
			blockIndex[*blockNode.Hash] = blockNode

			// Find the parent of this block, which should already have been read
			// in and connect it. Skip the genesis block, which has height 0. Also
			// skip the block if its PrevBlockHash is empty, which will be true for
			// the BitcoinStartBlockNode.
			//
			// TODO: There is room for optimization here by keeping a reference to
			// the last node we've iterated over and checking if that node is the
			// parent. Doing this would avoid an expensive hashmap check to get
			// the parent by its block hash.
			if blockNode.Height == 0 || (*blockNode.Header.PrevBlockHash == BlockHash{}) {
				continue
			}
			if parent, ok := blockIndex[*blockNode.Header.PrevBlockHash]; ok {
				// We found the parent node so connect it.
				blockNode.Parent = parent
			} else {
				// In this case we didn't find the parent so error. There shouldn't
				// be any unconnectedTxns in our block index.
				return fmt.Errorf("GetBlockIndex: Could not find parent for blockNode: %+v", blockNode)
			}
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "GetBlockIndex: Problem reading block index from db")
	}

	return blockIndex, nil
}

func GetBestChain(tipNode *BlockNode, blockIndex map[BlockHash]*BlockNode) ([]*BlockNode, error) {
	reversedBestChain := []*BlockNode{}
	for tipNode != nil {
		if (tipNode.Status&StatusBlockValidated) == 0 &&
			(tipNode.Status&StatusBitcoinHeaderValidated) == 0 {

			return nil, fmt.Errorf("GetBestChain: Invalid node found in main chain: %+v", tipNode)
		}

		reversedBestChain = append(reversedBestChain, tipNode)
		tipNode = tipNode.Parent
	}

	bestChain := make([]*BlockNode, len(reversedBestChain))
	for ii := 0; ii < len(reversedBestChain); ii++ {
		bestChain[ii] = reversedBestChain[len(reversedBestChain)-1-ii]
	}

	return bestChain, nil
}

// RandomBytes returns a []byte with random values.
func RandomBytes(numBytes int32) []byte {
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		glog.Errorf("Problem reading random bytes: %v", err)
	}
	return randomBytes
}

// RandomBytesHex returns a hex string representing numBytes of
// entropy.
func RandomBytesHex(numBytes int32) string {
	return hex.EncodeToString(RandomBytes(numBytes))
}

// RandInt64 returns a random 64-bit int.
func RandInt64(max int64) int64 {
	val, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		glog.Errorf("Problem generating random int64: %v", err)
	}
	return val.Int64()
}

// RandInt32 returns a random 32-bit int.
func RandInt32(max int32) int32 {
	val, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	if err != nil {
		glog.Errorf("Problem generating random int32: %v", err)
	}
	if val.Int64() > math.MaxInt32 {
		glog.Errorf("Generated a random number out of range: %d (max: %d)", val.Int64(), math.MaxInt32)
	}
	// This cast is OK since we initialized the number to be
	// < MaxInt32 above.
	return int32(val.Int64())
}

// PPrintJSON prints a JSON object but pretty.
func PPrintJSON(xx interface{}) {
	yy, _ := json.MarshalIndent(xx, "", "  ")
	log.Println(string(yy))
}

func BlocksPerDuration(duration time.Duration, timeBetweenBlocks time.Duration) uint32 {
	return uint32(int64(duration) / int64(timeBetweenBlocks))
}

func PkToString(pk []byte, params *DeSoParams) string {
	return Base58CheckEncode(pk, false, params)
}

func PrivToString(priv []byte, params *DeSoParams) string {
	return Base58CheckEncode(priv, true, params)
}

func PkToStringMainnet(pk []byte) string {
	return Base58CheckEncode(pk, false, &DeSoMainnetParams)
}

func PkToStringBoth(pk []byte) string {
	return PkToStringMainnet(pk) + ":" + PkToStringTestnet(pk)
}

func PkToStringTestnet(pk []byte) string {
	return Base58CheckEncode(pk, false, &DeSoTestnetParams)
}

func DbGetTxindexTip(handle *badger.DB, snap *Snapshot) *BlockHash {
	return _getBlockHashForPrefix(handle, snap, Prefixes.PrefixTransactionIndexTip)
}

func DbPutTxindexTipWithTxn(txn *badger.Txn, snap *Snapshot, tipHash *BlockHash) error {
	return DBSetWithTxn(txn, snap, Prefixes.PrefixTransactionIndexTip, tipHash[:])
}

func DbPutTxindexTip(handle *badger.DB, snap *Snapshot, tipHash *BlockHash) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbPutTxindexTipWithTxn(txn, snap, tipHash)
	})
}

func _DbTxindexPublicKeyNextIndexPrefix(publicKey []byte) []byte {
	return append(append([]byte{}, Prefixes.PrefixPublicKeyToNextIndex...), publicKey...)
}

func DbTxindexPublicKeyPrefix(publicKey []byte) []byte {
	return append(append([]byte{}, Prefixes.PrefixPublicKeyIndexToTransactionIDs...), publicKey...)
}

func DbTxindexPublicKeyIndexToTxnKey(publicKey []byte, index uint32) []byte {
	prefix := DbTxindexPublicKeyPrefix(publicKey)
	return append(prefix, _EncodeUint32(index)...)
}

func DbGetTxindexTxnsForPublicKeyWithTxn(txn *badger.Txn, publicKey []byte) []*BlockHash {
	txIDs := []*BlockHash{}
	_, valsFound, err := _enumerateKeysForPrefixWithTxn(txn, DbTxindexPublicKeyPrefix(publicKey))
	if err != nil {
		return txIDs
	}
	for _, txIDBytes := range valsFound {
		blockHash := &BlockHash{}
		copy(blockHash[:], txIDBytes[:])
		txIDs = append(txIDs, blockHash)
	}

	return txIDs
}

func DbGetTxindexTxnsForPublicKey(handle *badger.DB, publicKey []byte) []*BlockHash {
	txIDs := []*BlockHash{}
	handle.Update(func(txn *badger.Txn) error {
		txIDs = DbGetTxindexTxnsForPublicKeyWithTxn(txn, publicKey)
		return nil
	})
	return txIDs
}

func _DbGetTxindexNextIndexForPublicKeBySeekWithTxn(txn *badger.Txn, publicKey []byte) uint64 {
	dbPrefixx := DbTxindexPublicKeyPrefix(publicKey)

	opts := badger.DefaultIteratorOptions

	opts.PrefetchValues = false

	// Go in reverse order.
	opts.Reverse = true

	it := txn.NewIterator(opts)
	defer it.Close()
	// Since we iterate backwards, the prefix must be bigger than all possible
	// counts that could actually exist. We use four bytes since the index is
	// encoded as a 32-bit big-endian byte slice, which will be four bytes long.
	maxBigEndianUint32Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	prefix := append([]byte{}, dbPrefixx...)
	prefix = append(prefix, maxBigEndianUint32Bytes...)
	for it.Seek(prefix); it.ValidForPrefix(dbPrefixx); it.Next() {
		countKey := it.Item().Key()

		// Strip the prefix off the key and check its length. If it contains
		// a big-endian uint32 then it should be at least four bytes.
		countKey = countKey[len(dbPrefixx):]
		if len(countKey) < len(maxBigEndianUint32Bytes) {
			glog.Errorf("DbGetTxindexNextIndexForPublicKey: Invalid public key "+
				"index key length %d should be at least %d",
				len(countKey), len(maxBigEndianUint32Bytes))
			return 0
		}

		countVal := DecodeUint32(countKey[:len(maxBigEndianUint32Bytes)])
		return uint64(countVal + 1)
	}
	// If we get here it means we didn't find anything in the db so return zero.
	return 0
}

func DbGetTxindexNextIndexForPublicKey(handle *badger.DB, snap *Snapshot, publicKey []byte) *uint64 {
	var nextIndex *uint64
	handle.View(func(txn *badger.Txn) error {
		nextIndex = _DbGetTxindexNextIndexForPublicKeyWithTxn(txn, snap, publicKey)
		return nil
	})
	return nextIndex
}

func _DbGetTxindexNextIndexForPublicKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte) *uint64 {
	key := _DbTxindexPublicKeyNextIndexPrefix(publicKey)
	valBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// If we haven't seen this public key yet, we won't have a next index for this key yet, so return 0.
		if errors.Is(err, badger.ErrKeyNotFound) {
			nextIndexVal := _DbGetTxindexNextIndexForPublicKeBySeekWithTxn(txn, publicKey)
			return &nextIndexVal
		} else {
			return nil
		}
	}
	nextIndexVal, bytesRead := Uvarint(valBytes)
	if bytesRead <= 0 {
		return nil
	}
	return &nextIndexVal

}

func DbPutTxindexNextIndexForPublicKeyWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, nextIndex uint64) error {

	key := _DbTxindexPublicKeyNextIndexPrefix(publicKey)
	valBuf := UintToBuf(nextIndex)

	return DBSetWithTxn(txn, snap, key, valBuf)
}

func DbDeleteTxindexNextIndexForPublicKeyWithTxn(txn *badger.Txn, snap *Snapshot, publicKey []byte) error {
	key := _DbTxindexPublicKeyNextIndexPrefix(publicKey)
	return DBDeleteWithTxn(txn, snap, key)
}

func DbPutTxindexPublicKeyToTxnMappingSingleWithTxn(txn *badger.Txn, snap *Snapshot,
	publicKey []byte, txID *BlockHash) error {

	nextIndex := _DbGetTxindexNextIndexForPublicKeyWithTxn(txn, snap, publicKey)
	if nextIndex == nil {
		return fmt.Errorf("Error getting next index")
	}
	key := DbTxindexPublicKeyIndexToTxnKey(publicKey, uint32(*nextIndex))
	err := DbPutTxindexNextIndexForPublicKeyWithTxn(txn, snap, publicKey, uint64(*nextIndex+1))
	if err != nil {
		return err
	}
	return DBSetWithTxn(txn, snap, key, txID[:])
}

func DbDeleteTxindexPublicKeyToTxnMappingSingleWithTxn(txn *badger.Txn,
	snap *Snapshot, publicKey []byte, txID *BlockHash) error {

	// Get all the mappings corresponding to the public key passed in.
	// TODO: This is inefficient but reorgs are rare so whatever.
	txIDsInDB := DbGetTxindexTxnsForPublicKeyWithTxn(txn, publicKey)
	numMappingsInDB := len(txIDsInDB)

	// Loop over the list of txIDs and delete the one
	// corresponding to the passed-in transaction. Note we can assume that
	// only one occurrence exists in the list.
	// TODO: Looping backwards would be more efficient.
	for ii, singleTxID := range txIDsInDB {
		if *singleTxID == *txID {
			// If we get here it means the transaction we need to delete is at
			// this index.
			txIDsInDB = append(txIDsInDB[:ii], txIDsInDB[ii+1:]...)
			break
		}
	}

	// Delete all the mappings from the db.
	for pkIndex := 0; pkIndex < numMappingsInDB; pkIndex++ {
		key := DbTxindexPublicKeyIndexToTxnKey(publicKey, uint32(pkIndex))
		if err := DBDeleteWithTxn(txn, snap, key); err != nil {
			return err
		}
	}

	// Delete the next index for this public key
	err := DbDeleteTxindexNextIndexForPublicKeyWithTxn(txn, snap, publicKey)
	if err != nil {
		return err
	}

	// Re-add all the mappings to the db except the one we just deleted.
	for _, singleTxID := range txIDsInDB {
		if err := DbPutTxindexPublicKeyToTxnMappingSingleWithTxn(txn, snap, publicKey, singleTxID); err != nil {
			return err
		}
	}

	// At this point the db should contain all transactions except the one
	// that was deleted.
	return nil
}

func DbTxindexTxIDKey(txID *BlockHash) []byte {
	return append(append([]byte{}, Prefixes.PrefixTransactionIDToMetadata...), txID[:]...)
}

type AffectedPublicKey struct {
	PublicKeyBase58Check string
	// Metadata about how this public key was affected by the transaction.
	Metadata string
}

func (pk *AffectedPublicKey) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(pk.PublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(pk.Metadata))...)
	return data
}

func (pk *AffectedPublicKey) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	publicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AffectedPublicKey.Decode: problem reading PublicKeyBase58Check")
	}
	pk.PublicKeyBase58Check = string(publicKeyBase58CheckBytes)

	metadataBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AffectedPublicKey.Decode: problem reading Metadata")
	}
	pk.Metadata = string(metadataBytes)

	return nil
}

func (pk *AffectedPublicKey) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (pk *AffectedPublicKey) GetEncoderType() EncoderType {
	return EncoderTypeAffectedPublicKey
}

type BasicTransferTxindexMetadata struct {
	TotalInputNanos  uint64
	TotalOutputNanos uint64
	FeeNanos         uint64
	UtxoOpsDump      string
	UtxoOps          []*UtxoOperation
	DiamondLevel     int64
	PostHashHex      string
}

func (txnMeta *BasicTransferTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, UintToBuf(txnMeta.TotalInputNanos)...)
	data = append(data, UintToBuf(txnMeta.TotalOutputNanos)...)
	data = append(data, UintToBuf(txnMeta.FeeNanos)...)
	data = append(data, EncodeByteArray([]byte(txnMeta.UtxoOpsDump))...)
	data = append(data, UintToBuf(uint64(len(txnMeta.UtxoOps)))...)
	for _, utxoOp := range txnMeta.UtxoOps {
		data = append(data, EncodeToBytes(blockHeight, utxoOp, skipMetadata...)...)
	}
	data = append(data, UintToBuf(uint64(txnMeta.DiamondLevel))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.PostHashHex))...)
	return data
}

func (txnMeta *BasicTransferTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	txnMeta.TotalInputNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading TotalInputNanos")
	}

	txnMeta.TotalOutputNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading TotalOutputNanos")
	}

	txnMeta.FeeNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading FeeNanos")
	}

	utxoOpsDump, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading UtxoOpsDump")
	}
	txnMeta.UtxoOpsDump = string(utxoOpsDump)

	lenUtxoOps, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading len of UtxoOps")
	}
	for ; lenUtxoOps > 0; lenUtxoOps-- {
		utxoOp := &UtxoOperation{}
		if exists, err := DecodeFromBytes(utxoOp, rr); !exists || err != nil {
			return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading UtxoOps")
		}
		txnMeta.UtxoOps = append(txnMeta.UtxoOps, utxoOp)
	}

	uint64DiamondLevel, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading DiamondLevel")
	}
	txnMeta.DiamondLevel = int64(uint64DiamondLevel)

	postHashBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "BasicTransferTxindexMetadata.Decode: Problem reading PostHashHex")
	}
	txnMeta.PostHashHex = string(postHashBytes)

	return nil
}

func (txnMeta *BasicTransferTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *BasicTransferTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeBasicTransferTxindexMetadata
}

type BitcoinExchangeTxindexMetadata struct {
	BitcoinSpendAddress string
	// DeSoOutputPubKeyBase58Check = TransactorPublicKeyBase58Check
	SatoshisBurned uint64
	// NanosCreated = 0 OR TotalOutputNanos+FeeNanos
	NanosCreated uint64
	// TotalNanosPurchasedBefore = TotalNanosPurchasedAfter - NanosCreated
	TotalNanosPurchasedBefore uint64
	TotalNanosPurchasedAfter  uint64
	BitcoinTxnHash            string
}

func (txnMeta *BitcoinExchangeTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.BitcoinSpendAddress))...)
	data = append(data, UintToBuf(txnMeta.SatoshisBurned)...)
	data = append(data, UintToBuf(txnMeta.NanosCreated)...)
	data = append(data, UintToBuf(txnMeta.TotalNanosPurchasedBefore)...)
	data = append(data, UintToBuf(txnMeta.TotalNanosPurchasedAfter)...)
	data = append(data, EncodeByteArray([]byte(txnMeta.BitcoinTxnHash))...)
	return data
}

func (txnMeta *BitcoinExchangeTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	bitcoinSpendAddressBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeTxindexMetadata.Decode: problem decoding BitcoinSpendAddress")
	}
	txnMeta.BitcoinSpendAddress = string(bitcoinSpendAddressBytes)

	txnMeta.SatoshisBurned, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeTxindexMetadata.Decode: problem decoding SatoshisBurned")
	}

	txnMeta.NanosCreated, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeTxindexMetadata.Decode: problem decoding NanosCreated")
	}

	txnMeta.TotalNanosPurchasedBefore, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeTxindexMetadata.Decode: problem decoding TotalNanosPurchasedBefore")
	}
	txnMeta.TotalNanosPurchasedAfter, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeTxindexMetadata.Decode: problem decoding TotalNanosPurchasedAfter")
	}

	bitcoinTxnHashBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "BitcoinExchangeTxindexMetadata.Decode: problem decoding BitcoinTxnHash")
	}
	txnMeta.BitcoinTxnHash = string(bitcoinTxnHashBytes)

	return nil
}

func (txnMeta *BitcoinExchangeTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *BitcoinExchangeTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeBitcoinExchangeTxindexMetadata
}

type CreatorCoinTxindexMetadata struct {
	OperationType string
	// TransactorPublicKeyBase58Check = TransactorPublicKeyBase58Check
	// CreatorPublicKeyBase58Check in AffectedPublicKeys

	// Differs depending on OperationType.
	DeSoToSellNanos        uint64
	CreatorCoinToSellNanos uint64
	DeSoToAddNanos         uint64

	// Rosetta needs to know how much DESO was added or removed so it can
	// model the change to the total deso locked in the creator coin
	DESOLockedNanosDiff int64
}

func (txnMeta *CreatorCoinTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.OperationType))...)
	data = append(data, UintToBuf(txnMeta.DeSoToSellNanos)...)
	data = append(data, UintToBuf(txnMeta.CreatorCoinToSellNanos)...)
	data = append(data, UintToBuf(txnMeta.DeSoToAddNanos)...)
	data = append(data, UintToBuf(uint64(txnMeta.DESOLockedNanosDiff))...)
	return data
}

func (txnMeta *CreatorCoinTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	operationTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTxindexMetadata.Decode: Problem reading OperationType")
	}
	txnMeta.OperationType = string(operationTypeBytes)

	txnMeta.DeSoToSellNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTxindexMetadata.Decode: Problem reading DeSoToSellNanos")
	}

	txnMeta.CreatorCoinToSellNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTxindexMetadata.Decode: Problem reading CreatorCoinToSellNanos")
	}

	txnMeta.DeSoToAddNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTxindexMetadata.Decode: Problem reading DeSoToAddNanos")
	}

	uint64DESOLockedNanosDiff, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTxindexMetadata.Decode: Problem reading uint64DESOLockedNanosDiff")
	}
	txnMeta.DESOLockedNanosDiff = int64(uint64DESOLockedNanosDiff)

	return nil
}

func (txnMeta *CreatorCoinTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *CreatorCoinTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreatorCoinTxindexMetadata
}

type CreatorCoinTransferTxindexMetadata struct {
	CreatorUsername            string
	CreatorCoinToTransferNanos uint64
	DiamondLevel               int64
	PostHashHex                string
}

func (txnMeta *CreatorCoinTransferTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.CreatorUsername))...)
	data = append(data, UintToBuf(txnMeta.CreatorCoinToTransferNanos)...)
	data = append(data, UintToBuf(uint64(txnMeta.DiamondLevel))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.PostHashHex))...)
	return data
}

func (txnMeta *CreatorCoinTransferTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	creatorUsernameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTransferTxindexMetadata.Decode: problem reading CreatorUsername")
	}
	txnMeta.CreatorUsername = string(creatorUsernameBytes)

	txnMeta.CreatorCoinToTransferNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTransferTxindexMetadata.Decode: problem reading CreatorCoinToTransferNanos")
	}

	uint64DiamondLevel, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTransferTxindexMetadata.Decode: problem reading DiamondLevel")
	}
	txnMeta.DiamondLevel = int64(uint64DiamondLevel)

	postHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreatorCoinTransferTxindexMetadata.Decode: problem reading PostHashHex")
	}
	txnMeta.PostHashHex = string(postHashHexBytes)

	return nil
}

func (txnMeta *CreatorCoinTransferTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *CreatorCoinTransferTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreatorCoinTransferTxindexMetadata
}

type DAOCoinTransferTxindexMetadata struct {
	CreatorUsername        string
	DAOCoinToTransferNanos uint256.Int
}

func (txnMeta *DAOCoinTransferTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.CreatorUsername))...)
	data = append(data, EncodeUint256(&txnMeta.DAOCoinToTransferNanos)...)
	return data
}

func (txnMeta *DAOCoinTransferTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	creatorUsernameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTransferTxindexMetadata.Decode: Problem reading CreatorUsername")
	}
	txnMeta.CreatorUsername = string(creatorUsernameBytes)

	DAOCoinToTransferNanos, err := DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTransferTxindexMetadata.Decode: Problem reading DAOCoinToTransferNanos")
	}
	txnMeta.DAOCoinToTransferNanos = *DAOCoinToTransferNanos
	return nil
}

func (txnMeta *DAOCoinTransferTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *DAOCoinTransferTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinTransferTxindexMetadata
}

type DAOCoinTxindexMetadata struct {
	CreatorUsername           string
	OperationType             string
	CoinsToMintNanos          *uint256.Int
	CoinsToBurnNanos          *uint256.Int
	TransferRestrictionStatus string
}

func (txnMeta *DAOCoinTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.CreatorUsername))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.OperationType))...)

	data = append(data, EncodeUint256(txnMeta.CoinsToMintNanos)...)
	data = append(data, EncodeUint256(txnMeta.CoinsToBurnNanos)...)

	data = append(data, EncodeByteArray([]byte(txnMeta.TransferRestrictionStatus))...)
	return data
}

func (txnMeta *DAOCoinTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	creatorUsernameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTxindexMetadata.Decode: problem reading CreatorUsername")
	}
	txnMeta.CreatorUsername = string(creatorUsernameBytes)

	operationTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTxindexMetadata.Decode: problem reading OperationType")
	}
	txnMeta.OperationType = string(operationTypeBytes)

	txnMeta.CoinsToMintNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTxindexMetadata.Decode: problem reading CoinsToMintNanos")
	}

	txnMeta.CoinsToBurnNanos, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTxindexMetadata.Decode: problem reading CoinsToBurnNanos")
	}

	transferRestrictionStatusBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinTxindexMetadata.Decode: problem reading TransferRestrictionStatus")
	}
	txnMeta.TransferRestrictionStatus = string(transferRestrictionStatusBytes)

	return nil
}

func (txnMeta *DAOCoinTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *DAOCoinTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinTxindexMetadata
}

type FilledDAOCoinLimitOrderMetadata struct {
	TransactorPublicKeyBase58Check string
	BuyingDAOCoinCreatorPublicKey  string
	SellingDAOCoinCreatorPublicKey string
	CoinQuantityInBaseUnitsBought  *uint256.Int
	CoinQuantityInBaseUnitsSold    *uint256.Int
	IsFulfilled                    bool
}

func (orderMeta *FilledDAOCoinLimitOrderMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(orderMeta.TransactorPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(orderMeta.BuyingDAOCoinCreatorPublicKey))...)
	data = append(data, EncodeByteArray([]byte(orderMeta.SellingDAOCoinCreatorPublicKey))...)
	data = append(data, EncodeUint256(orderMeta.CoinQuantityInBaseUnitsBought)...)
	data = append(data, EncodeUint256(orderMeta.CoinQuantityInBaseUnitsSold)...)
	data = append(data, BoolToByte(orderMeta.IsFulfilled))

	return data
}

func (orderMeta *FilledDAOCoinLimitOrderMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	// TransactorPublicKeyBase58Check
	transactorPublicKeyBase58Check, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimitOrderMetadata.Decode: Problem reading TransactorPublicKeyBase58Check")
	}
	orderMeta.TransactorPublicKeyBase58Check = string(transactorPublicKeyBase58Check)

	// BuyingDAOCoinCreatorPublicKey
	buyingDAOCoinCreatorPublicKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactorPublicKeyBase58Check.Decode: Problem reading BuyingDAOCoinCreatorPublicKey")
	}
	orderMeta.BuyingDAOCoinCreatorPublicKey = string(buyingDAOCoinCreatorPublicKey)

	// SellingDAOCoinCreatorPublicKey
	sellingDAOCoinCreatorPublicKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimitOrderMetadata.Decode: Problem reading SellingDAOCoinCreatorPublicKey")
	}
	orderMeta.SellingDAOCoinCreatorPublicKey = string(sellingDAOCoinCreatorPublicKey)

	// CoinQuantityInBaseUnitsBought
	orderMeta.CoinQuantityInBaseUnitsBought, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimitOrderMetadata.Decode: Problem reading CoinQuantityInBaseUnitsBought")
	}

	// CoinQuantityInBaseUnitsSold
	orderMeta.CoinQuantityInBaseUnitsSold, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimitOrderMetadata.Decode: Problem reading CoinQuantityInBaseUnitsSold")
	}

	orderMeta.IsFulfilled, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "FilledDAOCoinLimitOrderMetadata.Decode: Problem reading IsFulfilled")
	}
	return nil
}

func (orderMeta *FilledDAOCoinLimitOrderMetadata) GetVersionByte(blockHeight uint64) byte {
	return byte(0)
}

func (orderMeta *FilledDAOCoinLimitOrderMetadata) GetEncoderType() EncoderType {
	return EncoderTypeFilledDAOCoinLimitOrderMetadata
}

type DAOCoinLimitOrderTxindexMetadata struct {
	BuyingDAOCoinCreatorPublicKey             string
	SellingDAOCoinCreatorPublicKey            string
	ScaledExchangeRateCoinsToSellPerCoinToBuy *uint256.Int
	QuantityToFillInBaseUnits                 *uint256.Int
	FilledDAOCoinLimitOrdersMetadata          []*FilledDAOCoinLimitOrderMetadata
}

func (daoMeta *DAOCoinLimitOrderTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(daoMeta.BuyingDAOCoinCreatorPublicKey))...)
	data = append(data, EncodeByteArray([]byte(daoMeta.SellingDAOCoinCreatorPublicKey))...)
	data = append(data, EncodeUint256(daoMeta.ScaledExchangeRateCoinsToSellPerCoinToBuy)...)
	data = append(data, EncodeUint256(daoMeta.QuantityToFillInBaseUnits)...)

	data = append(data, UintToBuf(uint64(len(daoMeta.FilledDAOCoinLimitOrdersMetadata)))...)
	for _, order := range daoMeta.FilledDAOCoinLimitOrdersMetadata {
		data = append(data, EncodeToBytes(blockHeight, order)...)
	}
	return data
}

func (daoMeta *DAOCoinLimitOrderTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {

	buyingDAOCoinCreatorPublicKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderTxindexMetadata.Decode: Problem reading BuyingDAOCoinCreatorPublicKey")
	}
	daoMeta.BuyingDAOCoinCreatorPublicKey = string(buyingDAOCoinCreatorPublicKey)

	sellingDAOCoinCreatorPublicKey, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderTxindexMetadata.Decode: Problem reading SellingDAOCoinCreatorPublicKey")
	}
	daoMeta.SellingDAOCoinCreatorPublicKey = string(sellingDAOCoinCreatorPublicKey)

	daoMeta.ScaledExchangeRateCoinsToSellPerCoinToBuy, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderTxindexMetadata.Decode: Problem reading ScaledExchangeRateCoinsToSellPerCoinToBuy")
	}

	daoMeta.QuantityToFillInBaseUnits, err = DecodeUint256(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderTxindexMetadata.Decode: Problem reading QuantityToFillInBaseUnits")
	}

	lenFilledDAOCoinLimitOrdersMetadata, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "DAOCoinLimitOrderTxindexMetadata.Decode: Problem reading len lenFilledDAOCoinLimitOrdersMetadata")
	}
	for ; lenFilledDAOCoinLimitOrdersMetadata > 0; lenFilledDAOCoinLimitOrdersMetadata-- {
		filledDAOCoinLimitOrderMetadata := &FilledDAOCoinLimitOrderMetadata{}
		if exist, err := DecodeFromBytes(filledDAOCoinLimitOrderMetadata, rr); !exist || err != nil {
			return errors.Wrapf(err, "DAOCoinLimitOrderTxindexMetadata.Decode: Problem reading len FilledDAOCoinLimitOrdersMetadata")
		}
		daoMeta.FilledDAOCoinLimitOrdersMetadata = append(daoMeta.FilledDAOCoinLimitOrdersMetadata, filledDAOCoinLimitOrderMetadata)
	}
	return nil
}

func (daoMeta *DAOCoinLimitOrderTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return byte(0)
}

func (daoMeta *DAOCoinLimitOrderTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeDAOCoinLimitOrderTxindexMetadata
}

type UpdateProfileTxindexMetadata struct {
	ProfilePublicKeyBase58Check string

	NewUsername    string
	NewDescription string
	NewProfilePic  string

	NewCreatorBasisPoints uint64

	NewStakeMultipleBasisPoints uint64

	IsHidden bool
}

func (txnMeta *UpdateProfileTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.ProfilePublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.NewUsername))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.NewDescription))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.NewProfilePic))...)
	data = append(data, UintToBuf(txnMeta.NewCreatorBasisPoints)...)
	data = append(data, UintToBuf(txnMeta.NewStakeMultipleBasisPoints)...)
	data = append(data, BoolToByte(txnMeta.IsHidden))

	return data
}

func (txnMeta *UpdateProfileTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	profilePublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading ProfilePublicKeyBase58Check")
	}
	txnMeta.ProfilePublicKeyBase58Check = string(profilePublicKeyBase58CheckBytes)

	newUsernameBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading NewUsername")
	}
	txnMeta.NewUsername = string(newUsernameBytes)

	newDescriptionBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading NewDescription")
	}
	txnMeta.NewDescription = string(newDescriptionBytes)

	newProfilePicBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading NewProfilePic")
	}
	txnMeta.NewProfilePic = string(newProfilePicBytes)

	txnMeta.NewCreatorBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading NewCreatorBasisPoints")
	}

	txnMeta.NewStakeMultipleBasisPoints, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading NewStakeMultipleBasisPoints")
	}

	txnMeta.IsHidden, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateProfileTxindexMetadata.Decode: problem reading IsHidden")
	}
	return nil
}

func (txnMeta *UpdateProfileTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *UpdateProfileTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUpdateProfileTxindexMetadata
}

type SubmitPostTxindexMetadata struct {
	PostHashBeingModifiedHex string
	// PosterPublicKeyBase58Check = TransactorPublicKeyBase58Check

	// If this is a reply to an existing post, then the ParentPostHashHex
	ParentPostHashHex string
	// ParentPosterPublicKeyBase58Check in AffectedPublicKeys

	// The profiles that are mentioned are in the AffectedPublicKeys
	// MentionedPublicKeyBase58Check in AffectedPublicKeys
}

func (txnMeta *SubmitPostTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.PostHashBeingModifiedHex))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.ParentPostHashHex))...)
	return data
}

func (txnMeta *SubmitPostTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	postHashBeingModifiedHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "SubmitPostTxindexMetadata.Decode: problem reading PostHashBeingModifiedHex")
	}
	txnMeta.PostHashBeingModifiedHex = string(postHashBeingModifiedHexBytes)

	parentPostHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "SubmitPostTxindexMetadata.Decode: problem reading ParentPostHashHex")
	}
	txnMeta.ParentPostHashHex = string(parentPostHashHexBytes)

	return nil
}

func (txnMeta *SubmitPostTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *SubmitPostTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeSubmitPostTxindexMetadata
}

type LikeTxindexMetadata struct {
	// LikerPublicKeyBase58Check = TransactorPublicKeyBase58Check
	IsUnlike bool

	PostHashHex string
	// PosterPublicKeyBase58Check in AffectedPublicKeys
}

func (txnMeta *LikeTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, BoolToByte(txnMeta.IsUnlike))
	data = append(data, EncodeByteArray([]byte(txnMeta.PostHashHex))...)
	return data
}

func (txnMeta *LikeTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	txnMeta.IsUnlike, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "LikeTxindexMetadata.Decode: Emptry IsUnlike")
	}
	postHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "LikeTxindexMetadata.Decode: problem reading PostHashHex")
	}
	txnMeta.PostHashHex = string(postHashHexBytes)

	return nil
}

func (txnMeta *LikeTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *LikeTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeLikeTxindexMetadata
}

type FollowTxindexMetadata struct {
	// FollowerPublicKeyBase58Check = TransactorPublicKeyBase58Check
	// FollowedPublicKeyBase58Check in AffectedPublicKeys

	IsUnfollow bool
}

func (txnMeta *FollowTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, BoolToByte(txnMeta.IsUnfollow))
	return data
}

func (txnMeta *FollowTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error
	txnMeta.IsUnfollow, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "FollowTxindexMetadata.Decode: Problem reading IsUnfollow")
	}
	return nil
}

func (txnMeta *FollowTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *FollowTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeFollowTxindexMetadata
}

type PrivateMessageTxindexMetadata struct {
	// SenderPublicKeyBase58Check = TransactorPublicKeyBase58Check
	// RecipientPublicKeyBase58Check in AffectedPublicKeys

	TimestampNanos uint64
}

func (txnMeta *PrivateMessageTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, UintToBuf(txnMeta.TimestampNanos)...)
	return data
}

func (txnMeta *PrivateMessageTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	txnMeta.TimestampNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "PrivateMessageTxindexMetadata.Decode: Problem reading TimestampNanos")
	}
	return nil
}

func (txnMeta *PrivateMessageTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *PrivateMessageTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypePrivateMessageTxindexMetadata
}

type SwapIdentityTxindexMetadata struct {
	// ParamUpdater = TransactorPublicKeyBase58Check

	FromPublicKeyBase58Check string
	ToPublicKeyBase58Check   string

	// Rosetta needs this information to track creator coin balances
	FromDeSoLockedNanos uint64
	ToDeSoLockedNanos   uint64
}

func (txnMeta *SwapIdentityTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.FromPublicKeyBase58Check))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.ToPublicKeyBase58Check))...)
	data = append(data, UintToBuf(txnMeta.FromDeSoLockedNanos)...)
	data = append(data, UintToBuf(txnMeta.ToDeSoLockedNanos)...)
	return data
}

func (txnMeta *SwapIdentityTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	fromPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "SwapIdentityTxindexMetadata.Decode: Problem reading FromPublicKeyBase58Check")
	}
	txnMeta.FromPublicKeyBase58Check = string(fromPublicKeyBase58CheckBytes)

	toPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "SwapIdentityTxindexMetadata.Decode: Problem reading ToPublicKeyBase58Check")
	}
	txnMeta.ToPublicKeyBase58Check = string(toPublicKeyBase58CheckBytes)

	txnMeta.FromDeSoLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "SwapIdentityTxindexMetadata.Decode: Problem reading FromDeSoLockedNanos")
	}
	txnMeta.ToDeSoLockedNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "SwapIdentityTxindexMetadata.Decode: Problem reading ToDeSoLockedNanos")
	}
	return nil
}

func (txnMeta *SwapIdentityTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *SwapIdentityTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeSwapIdentityTxindexMetadata
}

type NFTRoyaltiesMetadata struct {
	CreatorCoinRoyaltyNanos     uint64
	CreatorRoyaltyNanos         uint64
	CreatorPublicKeyBase58Check string
	// We omit the maps when empty to save some space.
	AdditionalCoinRoyaltiesMap map[string]uint64 `json:",omitempty"`
	AdditionalDESORoyaltiesMap map[string]uint64 `json:",omitempty"`
}

func (txnMeta *NFTRoyaltiesMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, UintToBuf(txnMeta.CreatorRoyaltyNanos)...)
	data = append(data, UintToBuf(txnMeta.CreatorRoyaltyNanos)...)
	data = append(data, EncodeByteArray([]byte(txnMeta.CreatorPublicKeyBase58Check))...)
	data = append(data, EncodeMapStringUint64(txnMeta.AdditionalCoinRoyaltiesMap)...)
	data = append(data, EncodeMapStringUint64(txnMeta.AdditionalDESORoyaltiesMap)...)
	return data
}

func (txnMeta *NFTRoyaltiesMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	txnMeta.CreatorCoinRoyaltyNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTRoyaltiesMetadata.Decode: Problem reading CreatorCoinRoyaltyNanos")
	}
	txnMeta.CreatorRoyaltyNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTRoyaltiesMetadata.Decode: Problem reading CreatorRoyaltyNanos")
	}
	creatorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTRoyaltiesMetadata.Decode: Problem reading CreatorPublicKeyBase58Check")
	}
	txnMeta.CreatorPublicKeyBase58Check = string(creatorPublicKeyBase58CheckBytes)

	txnMeta.AdditionalCoinRoyaltiesMap, err = DecodeMapStringUint64(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTRoyaltiesMetadata.Decode: Problem reading AdditionalCoinRoyaltiesMap")
	}
	txnMeta.AdditionalDESORoyaltiesMap, err = DecodeMapStringUint64(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTRoyaltiesMetadata.Decode: Problem reading AdditionalDESORoyaltiesMap")
	}
	return nil
}

func (txnMeta *NFTRoyaltiesMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *NFTRoyaltiesMetadata) GetEncoderType() EncoderType {
	return EncoderTypeNFTRoyaltiesMetadata
}

type NFTBidTxindexMetadata struct {
	NFTPostHashHex            string
	SerialNumber              uint64
	BidAmountNanos            uint64
	IsBuyNowBid               bool
	OwnerPublicKeyBase58Check string
	// We omit the empty object here as a bid that doesn't trigger a "buy now" operation will have no royalty metadata
	NFTRoyaltiesMetadata *NFTRoyaltiesMetadata `json:",omitempty"`
}

func (txnMeta *NFTBidTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, UintToBuf(txnMeta.SerialNumber)...)
	data = append(data, UintToBuf(txnMeta.BidAmountNanos)...)
	data = append(data, BoolToByte(txnMeta.IsBuyNowBid))
	data = append(data, EncodeByteArray([]byte(txnMeta.OwnerPublicKeyBase58Check))...)
	data = append(data, EncodeToBytes(blockHeight, txnMeta.NFTRoyaltiesMetadata, skipMetadata...)...)
	return data
}

func (txnMeta *NFTBidTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidTxindexMetadata.Decode: Problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHexBytes)

	txnMeta.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidTxindexMetadata.Decode: Problem reading SerialNumber")
	}
	txnMeta.BidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidTxindexMetadata.Decode: Problem reading BidAmountNanos")
	}
	txnMeta.IsBuyNowBid, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidTxindexMetadata.Decode: Problem reading IsBuyNowBid")
	}

	ownerPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTBidTxindexMetadata.Decode: Problem reading OwnerPublicKeyBase58Check")
	}
	txnMeta.OwnerPublicKeyBase58Check = string(ownerPublicKeyBase58CheckBytes)

	txnMeta.NFTRoyaltiesMetadata = &NFTRoyaltiesMetadata{}
	if exists, err := DecodeFromBytes(txnMeta.NFTRoyaltiesMetadata, rr); !exists || err != nil {
		return errors.Wrapf(err, "NFTBidTxindexMetadata.Decode: Problem reading NFTRoyaltiesMetadata")
	}

	return nil
}

func (txnMeta *NFTBidTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *NFTBidTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeNFTBidTxindexMetadata
}

type AcceptNFTBidTxindexMetadata struct {
	NFTPostHashHex       string
	SerialNumber         uint64
	BidAmountNanos       uint64
	NFTRoyaltiesMetadata *NFTRoyaltiesMetadata
}

func (txnMeta *AcceptNFTBidTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, UintToBuf(txnMeta.SerialNumber)...)
	data = append(data, UintToBuf(txnMeta.BidAmountNanos)...)
	data = append(data, EncodeToBytes(blockHeight, txnMeta.NFTRoyaltiesMetadata, skipMetadata...)...)

	return data
}

func (txnMeta *AcceptNFTBidTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidTxindexMetadata.Decode: problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHexBytes)

	txnMeta.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidTxindexMetadata.Decode: problem reading SerialNumber")
	}
	txnMeta.BidAmountNanos, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTBidTxindexMetadata.Decode: problem reading BidAmountNanos")
	}
	txnMeta.NFTRoyaltiesMetadata = &NFTRoyaltiesMetadata{}
	if exists, err := DecodeFromBytes(txnMeta.NFTRoyaltiesMetadata, rr); !exists || err != nil {
		return errors.Wrapf(err, "AcceptNFTBidTxindexMetadata.Decode: problem reading NFTRoyaltiesMetadata")
	}
	return nil
}

func (txnMeta *AcceptNFTBidTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *AcceptNFTBidTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeAcceptNFTBidTxindexMetadata
}

type NFTTransferTxindexMetadata struct {
	NFTPostHashHex string
	SerialNumber   uint64
}

func (txnMeta *NFTTransferTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, UintToBuf(txnMeta.SerialNumber)...)

	return data
}

func (txnMeta *NFTTransferTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTTransferTxindexMetadata.Decode: problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHexBytes)

	txnMeta.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "NFTTransferTxindexMetadata.Decode: problem reading SerialNumber")
	}

	return nil
}

func (txnMeta *NFTTransferTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *NFTTransferTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeNFTTransferTxindexMetadata
}

type AcceptNFTTransferTxindexMetadata struct {
	NFTPostHashHex string
	SerialNumber   uint64
}

func (txnMeta *AcceptNFTTransferTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, UintToBuf(txnMeta.SerialNumber)...)
	return data
}

func (txnMeta *AcceptNFTTransferTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHex, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTTransferTxindexMetadata.Decode: problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHex)

	txnMeta.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "AcceptNFTTransferTxindexMetadata.Decode: problem reading SerialNumber")
	}
	return nil
}

func (txnMeta *AcceptNFTTransferTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *AcceptNFTTransferTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeAcceptNFTTransferTxindexMetadata
}

type BurnNFTTxindexMetadata struct {
	NFTPostHashHex string
	SerialNumber   uint64
}

func (txnMeta *BurnNFTTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, UintToBuf(txnMeta.SerialNumber)...)

	return data
}

func (txnMeta *BurnNFTTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHex, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "BurnNFTTxindexMetadata.Decode: problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHex)

	txnMeta.SerialNumber, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "BurnNFTTxindexMetadata.Decode: problem reading SerialNumber")
	}
	return nil
}

func (txnMeta *BurnNFTTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *BurnNFTTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeBurnNFTTxindexMetadata
}

type CreateNFTTxindexMetadata struct {
	NFTPostHashHex             string
	AdditionalCoinRoyaltiesMap map[string]uint64 `json:",omitempty"`
	AdditionalDESORoyaltiesMap map[string]uint64 `json:",omitempty"`
}

func (txnMeta *CreateNFTTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, EncodeMapStringUint64(txnMeta.AdditionalCoinRoyaltiesMap)...)
	data = append(data, EncodeMapStringUint64(txnMeta.AdditionalDESORoyaltiesMap)...)

	return data
}

func (txnMeta *CreateNFTTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTTxindexMetadata.Decode: problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHexBytes)

	txnMeta.AdditionalCoinRoyaltiesMap, err = DecodeMapStringUint64(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTTxindexMetadata.Decode: problem reading AdditionalCoinRoyaltiesMap")
	}
	txnMeta.AdditionalDESORoyaltiesMap, err = DecodeMapStringUint64(rr)
	if err != nil {
		return errors.Wrapf(err, "CreateNFTTxindexMetadata.Decode: problem reading AdditionalDESORoyaltiesMap")
	}

	return nil
}

func (txnMeta *CreateNFTTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *CreateNFTTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeCreateNFTTxindexMetadata
}

type UpdateNFTTxindexMetadata struct {
	NFTPostHashHex string
	IsForSale      bool
}

func (txnMeta *UpdateNFTTxindexMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.NFTPostHashHex))...)
	data = append(data, BoolToByte(txnMeta.IsForSale))

	return data
}

func (txnMeta *UpdateNFTTxindexMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	NFTPostHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateNFTTxindexMetadata.Decode: Problem reading NFTPostHashHex")
	}
	txnMeta.NFTPostHashHex = string(NFTPostHashHexBytes)
	txnMeta.IsForSale, err = ReadBoolByte(rr)
	if err != nil {
		return errors.Wrapf(err, "UpdateNFTTxindexMetadata.Decode: Problem reading IsForSale")

	}
	return nil
}

func (txnMeta *UpdateNFTTxindexMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *UpdateNFTTxindexMetadata) GetEncoderType() EncoderType {
	return EncoderTypeUpdateNFTTxindexMetadata
}

type TransactionMetadata struct {
	BlockHashHex    string
	TxnIndexInBlock uint64
	TxnType         string
	// All transactions have a public key who executed the transaction and some
	// public keys that are affected by the transaction. Notifications are created
	// for the affected public keys. _getPublicKeysForTxn uses this to set entries in the
	// database.
	TransactorPublicKeyBase58Check string
	AffectedPublicKeys             []*AffectedPublicKey

	// We store these outputs so we don't have to load the full transaction from disk
	// when looking up output amounts
	TxnOutputs []*DeSoOutput

	BasicTransferTxindexMetadata       *BasicTransferTxindexMetadata       `json:",omitempty"`
	BitcoinExchangeTxindexMetadata     *BitcoinExchangeTxindexMetadata     `json:",omitempty"`
	CreatorCoinTxindexMetadata         *CreatorCoinTxindexMetadata         `json:",omitempty"`
	CreatorCoinTransferTxindexMetadata *CreatorCoinTransferTxindexMetadata `json:",omitempty"`
	UpdateProfileTxindexMetadata       *UpdateProfileTxindexMetadata       `json:",omitempty"`
	SubmitPostTxindexMetadata          *SubmitPostTxindexMetadata          `json:",omitempty"`
	LikeTxindexMetadata                *LikeTxindexMetadata                `json:",omitempty"`
	FollowTxindexMetadata              *FollowTxindexMetadata              `json:",omitempty"`
	PrivateMessageTxindexMetadata      *PrivateMessageTxindexMetadata      `json:",omitempty"`
	SwapIdentityTxindexMetadata        *SwapIdentityTxindexMetadata        `json:",omitempty"`
	NFTBidTxindexMetadata              *NFTBidTxindexMetadata              `json:",omitempty"`
	AcceptNFTBidTxindexMetadata        *AcceptNFTBidTxindexMetadata        `json:",omitempty"`
	NFTTransferTxindexMetadata         *NFTTransferTxindexMetadata         `json:",omitempty"`
	AcceptNFTTransferTxindexMetadata   *AcceptNFTTransferTxindexMetadata   `json:",omitempty"`
	BurnNFTTxindexMetadata             *BurnNFTTxindexMetadata             `json:",omitempty"`
	DAOCoinTxindexMetadata             *DAOCoinTxindexMetadata             `json:",omitempty"`
	DAOCoinTransferTxindexMetadata     *DAOCoinTransferTxindexMetadata     `json:",omitempty"`
	CreateNFTTxindexMetadata           *CreateNFTTxindexMetadata           `json:",omitempty"`
	UpdateNFTTxindexMetadata           *UpdateNFTTxindexMetadata           `json:",omitempty"`
	DAOCoinLimitOrderTxindexMetadata   *DAOCoinLimitOrderTxindexMetadata   `json:",omitempty"`
}

func (txnMeta *TransactionMetadata) RawEncodeWithoutMetadata(blockHeight uint64, skipMetadata ...bool) []byte {
	var data []byte

	data = append(data, EncodeByteArray([]byte(txnMeta.BlockHashHex))...)
	data = append(data, UintToBuf(txnMeta.TxnIndexInBlock)...)
	data = append(data, EncodeByteArray([]byte(txnMeta.TxnType))...)
	data = append(data, EncodeByteArray([]byte(txnMeta.TransactorPublicKeyBase58Check))...)

	data = append(data, UintToBuf(uint64(len(txnMeta.AffectedPublicKeys)))...)
	for _, affectedKey := range txnMeta.AffectedPublicKeys {
		data = append(data, EncodeToBytes(blockHeight, affectedKey, skipMetadata...)...)
	}

	data = append(data, UintToBuf(uint64(len(txnMeta.TxnOutputs)))...)
	for _, output := range txnMeta.TxnOutputs {
		data = append(data, EncodeToBytes(blockHeight, output, skipMetadata...)...)
	}

	// encoding BasicTransferTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.BasicTransferTxindexMetadata, skipMetadata...)...)
	// encoding BitcoinExchangeTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.BitcoinExchangeTxindexMetadata, skipMetadata...)...)
	// encoding CreatorCoinTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.CreatorCoinTxindexMetadata, skipMetadata...)...)
	// encoding CreatorCoinTransferTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.CreatorCoinTransferTxindexMetadata, skipMetadata...)...)
	// encoding UpdateProfileTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.UpdateProfileTxindexMetadata, skipMetadata...)...)
	// encoding SubmitPostTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.SubmitPostTxindexMetadata, skipMetadata...)...)
	// encoding LikeTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.LikeTxindexMetadata, skipMetadata...)...)
	// encoding FollowTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.FollowTxindexMetadata, skipMetadata...)...)
	// encoding PrivateMessageTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.PrivateMessageTxindexMetadata, skipMetadata...)...)
	// encoding SwapIdentityTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.SwapIdentityTxindexMetadata, skipMetadata...)...)
	// encoding NFTBidTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.NFTBidTxindexMetadata, skipMetadata...)...)
	// encoding AcceptNFTBidTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.AcceptNFTBidTxindexMetadata, skipMetadata...)...)
	// encoding NFTTransferTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.NFTTransferTxindexMetadata, skipMetadata...)...)
	// encoding AcceptNFTTransferTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.AcceptNFTTransferTxindexMetadata, skipMetadata...)...)
	// encoding BurnNFTTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.BurnNFTTxindexMetadata, skipMetadata...)...)
	// encoding DAOCoinTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.DAOCoinTxindexMetadata, skipMetadata...)...)
	// encoding DAOCoinTransferTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.DAOCoinTransferTxindexMetadata, skipMetadata...)...)
	// encoding CreateNFTTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.CreateNFTTxindexMetadata, skipMetadata...)...)
	// encoding UpdateNFTTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.UpdateNFTTxindexMetadata, skipMetadata...)...)
	// encoding DAOCoinLimitOrderTxindexMetadata
	data = append(data, EncodeToBytes(blockHeight, txnMeta.DAOCoinLimitOrderTxindexMetadata, skipMetadata...)...)
	return data
}

func (txnMeta *TransactionMetadata) RawDecodeWithoutMetadata(blockHeight uint64, rr *bytes.Reader) error {
	var err error

	blockHashHexBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading BlockHashHexBytes")
	}
	txnMeta.BlockHashHex = string(blockHashHexBytes)

	txnMeta.TxnIndexInBlock, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading TxnIndexInBlock")
	}

	txnTypeBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading TxnType")
	}
	txnMeta.TxnType = string(txnTypeBytes)

	transactorPublicKeyBase58CheckBytes, err := DecodeByteArray(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading TransactorPublicKeyBase58Check")
	}
	txnMeta.TransactorPublicKeyBase58Check = string(transactorPublicKeyBase58CheckBytes)

	lenAffectedPublicKeys, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading len AffectedPublicKeys")
	}
	for ; lenAffectedPublicKeys > 0; lenAffectedPublicKeys-- {
		affectedPublicKey := &AffectedPublicKey{}
		if exists, err := DecodeFromBytes(affectedPublicKey, rr); !exists || err != nil {
			return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading AffectedPublicKey")
		}
		txnMeta.AffectedPublicKeys = append(txnMeta.AffectedPublicKeys, affectedPublicKey)
	}

	lenTxnOutputs, err := ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading len TxnOutputs")
	}
	for ; lenTxnOutputs > 0; lenTxnOutputs-- {
		txnOutput := &DeSoOutput{}
		if exists, err := DecodeFromBytes(txnOutput, rr); !exists || err != nil {
			return errors.Wrapf(err, "TransactionMetadata.Decode: problem reading TxnOutput")
		}
		txnMeta.TxnOutputs = append(txnMeta.TxnOutputs, txnOutput)
	}

	// decoding BasicTransferTxindexMetadata
	CopyBasicTransferTxindexMetadata := &BasicTransferTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyBasicTransferTxindexMetadata, rr); exist && err == nil {
		txnMeta.BasicTransferTxindexMetadata = CopyBasicTransferTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading BasicTransferTxindexMetadata")
	}
	// decoding BitcoinExchangeTxindexMetadata
	CopyBitcoinExchangeTxindexMetadata := &BitcoinExchangeTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyBitcoinExchangeTxindexMetadata, rr); exist && err == nil {
		txnMeta.BitcoinExchangeTxindexMetadata = CopyBitcoinExchangeTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading BitcoinExchangeTxindexMetadata")
	}
	// decoding CreatorCoinTxindexMetadata
	CopyCreatorCoinTxindexMetadata := &CreatorCoinTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyCreatorCoinTxindexMetadata, rr); exist && err == nil {
		txnMeta.CreatorCoinTxindexMetadata = CopyCreatorCoinTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading CreatorCoinTxindexMetadata")
	}
	// decoding CreatorCoinTransferTxindexMetadata
	CopyCreatorCoinTransferTxindexMetadata := &CreatorCoinTransferTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyCreatorCoinTransferTxindexMetadata, rr); exist && err == nil {
		txnMeta.CreatorCoinTransferTxindexMetadata = CopyCreatorCoinTransferTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading CreatorCoinTransferTxindexMetadata")
	}
	// decoding UpdateProfileTxindexMetadata
	CopyUpdateProfileTxindexMetadata := &UpdateProfileTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyUpdateProfileTxindexMetadata, rr); exist && err == nil {
		txnMeta.UpdateProfileTxindexMetadata = CopyUpdateProfileTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading UpdateProfileTxindexMetadata")
	}
	// decoding SubmitPostTxindexMetadata
	CopySubmitPostTxindexMetadata := &SubmitPostTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopySubmitPostTxindexMetadata, rr); exist && err == nil {
		txnMeta.SubmitPostTxindexMetadata = CopySubmitPostTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading SubmitPostTxindexMetadata")
	}
	// decoding LikeTxindexMetadata
	CopyLikeTxindexMetadata := &LikeTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyLikeTxindexMetadata, rr); exist && err == nil {
		txnMeta.LikeTxindexMetadata = CopyLikeTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading LikeTxindexMetadata")
	}
	// decoding FollowTxindexMetadata
	CopyFollowTxindexMetadata := &FollowTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyFollowTxindexMetadata, rr); exist && err == nil {
		txnMeta.FollowTxindexMetadata = CopyFollowTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading FollowTxindexMetadata")
	}
	// decoding PrivateMessageTxindexMetadata
	CopyPrivateMessageTxindexMetadata := &PrivateMessageTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyPrivateMessageTxindexMetadata, rr); exist && err == nil {
		txnMeta.PrivateMessageTxindexMetadata = CopyPrivateMessageTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading PrivateMessageTxindexMetadata")
	}
	// decoding SwapIdentityTxindexMetadata
	CopySwapIdentityTxindexMetadata := &SwapIdentityTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopySwapIdentityTxindexMetadata, rr); exist && err == nil {
		txnMeta.SwapIdentityTxindexMetadata = CopySwapIdentityTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading SwapIdentityTxindexMetadata")
	}
	// decoding NFTBidTxindexMetadata
	CopyNFTBidTxindexMetadata := &NFTBidTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyNFTBidTxindexMetadata, rr); exist && err == nil {
		txnMeta.NFTBidTxindexMetadata = CopyNFTBidTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading NFTBidTxindexMetadata")
	}
	// decoding AcceptNFTBidTxindexMetadata
	CopyAcceptNFTBidTxindexMetadata := &AcceptNFTBidTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyAcceptNFTBidTxindexMetadata, rr); exist && err == nil {
		txnMeta.AcceptNFTBidTxindexMetadata = CopyAcceptNFTBidTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading AcceptNFTBidTxindexMetadata")
	}
	// decoding NFTTransferTxindexMetadata
	CopyNFTTransferTxindexMetadata := &NFTTransferTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyNFTTransferTxindexMetadata, rr); exist && err == nil {
		txnMeta.NFTTransferTxindexMetadata = CopyNFTTransferTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading NFTTransferTxindexMetadata")
	}
	// decoding AcceptNFTTransferTxindexMetadata
	CopyAcceptNFTTransferTxindexMetadata := &AcceptNFTTransferTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyAcceptNFTTransferTxindexMetadata, rr); exist && err == nil {
		txnMeta.AcceptNFTTransferTxindexMetadata = CopyAcceptNFTTransferTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading AcceptNFTTransferTxindexMetadata")
	}
	// decoding BurnNFTTxindexMetadata
	CopyBurnNFTTxindexMetadata := &BurnNFTTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyBurnNFTTxindexMetadata, rr); exist && err == nil {
		txnMeta.BurnNFTTxindexMetadata = CopyBurnNFTTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading BurnNFTTxindexMetadata")
	}
	// decoding DAOCoinTxindexMetadata
	CopyDAOCoinTxindexMetadata := &DAOCoinTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyDAOCoinTxindexMetadata, rr); exist && err == nil {
		txnMeta.DAOCoinTxindexMetadata = CopyDAOCoinTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading DAOCoinTxindexMetadata")
	}
	// decoding DAOCoinTransferTxindexMetadata
	CopyDAOCoinTransferTxindexMetadata := &DAOCoinTransferTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyDAOCoinTransferTxindexMetadata, rr); exist && err == nil {
		txnMeta.DAOCoinTransferTxindexMetadata = CopyDAOCoinTransferTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading DAOCoinTransferTxindexMetadata")
	}
	// decoding CreateNFTTxindexMetadata
	CopyCreateNFTTxindexMetadata := &CreateNFTTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyCreateNFTTxindexMetadata, rr); exist && err == nil {
		txnMeta.CreateNFTTxindexMetadata = CopyCreateNFTTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading CreateNFTTxindexMetadata")
	}
	// decoding UpdateNFTTxindexMetadata
	CopyUpdateNFTTxindexMetadata := &UpdateNFTTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyUpdateNFTTxindexMetadata, rr); exist && err == nil {
		txnMeta.UpdateNFTTxindexMetadata = CopyUpdateNFTTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading UpdateNFTTxindexMetadata")
	}
	// decoding DAOCoinLimitOrderTxindexMetadata
	CopyDAOCoinLimitOrderTxindexMetadata := &DAOCoinLimitOrderTxindexMetadata{}
	if exist, err := DecodeFromBytes(CopyDAOCoinLimitOrderTxindexMetadata, rr); exist && err == nil {
		txnMeta.DAOCoinLimitOrderTxindexMetadata = CopyDAOCoinLimitOrderTxindexMetadata
	} else if err != nil {
		return errors.Wrapf(err, "TransactionMetadata.Decode: Problem reading DAOCoinLimitOrderTxindexMetadata")
	}
	return nil
}

func (txnMeta *TransactionMetadata) GetVersionByte(blockHeight uint64) byte {
	return 0
}

func (txnMeta *TransactionMetadata) GetEncoderType() EncoderType {
	return EncoderTypeTransactionMetadata
}

func DBCheckTxnExistenceWithTxn(txn *badger.Txn, snap *Snapshot, txID *BlockHash) bool {
	key := DbTxindexTxIDKey(txID)
	_, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return false
	}
	return true
}

func DbCheckTxnExistence(handle *badger.DB, snap *Snapshot, txID *BlockHash) bool {
	var exists bool
	handle.View(func(txn *badger.Txn) error {
		exists = DBCheckTxnExistenceWithTxn(txn, snap, txID)
		return nil
	})
	return exists
}

func DbGetTxindexTransactionRefByTxIDWithTxn(txn *badger.Txn, snap *Snapshot, txID *BlockHash) *TransactionMetadata {
	key := DbTxindexTxIDKey(txID)
	valObj := &TransactionMetadata{}

	valBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}
	rr := bytes.NewReader(valBytes)
	if exists, err := DecodeFromBytes(valObj, rr); !exists || err != nil {
		return nil
	}
	return valObj
}

func DbGetTxindexTransactionRefByTxID(handle *badger.DB, snap *Snapshot, txID *BlockHash) *TransactionMetadata {
	var valObj *TransactionMetadata
	handle.View(func(txn *badger.Txn) error {
		valObj = DbGetTxindexTransactionRefByTxIDWithTxn(txn, snap, txID)
		return nil
	})
	return valObj
}
func DbPutTxindexTransactionWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	txID *BlockHash, txnMeta *TransactionMetadata) error {

	key := append(append([]byte{}, Prefixes.PrefixTransactionIDToMetadata...), txID[:]...)
	return DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, txnMeta))
}

func DbPutTxindexTransaction(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	txID *BlockHash, txnMeta *TransactionMetadata) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutTxindexTransactionWithTxn(txn, snap, blockHeight, txID, txnMeta)
	})
}

func _getPublicKeysForTxn(
	txn *MsgDeSoTxn, txnMeta *TransactionMetadata, params *DeSoParams) map[PkMapKey]bool {

	// Collect the public keys in the transaction.
	publicKeys := make(map[PkMapKey]bool)

	// TODO: For AddStake transactions, we don't have a way of getting the implicit
	// outputs. This means that if you get paid from someone else staking to a post
	// after you, the output won't be explicitly included in the transaction, and so
	// it won't be added to our index. We should fix this at some point. I think the
	// "right way" to fix this problem is to index UTXOs rather than transactions (or
	// in addition to them).
	// TODO(updated): We can fix this by populating AffectedPublicKeys

	// Add the TransactorPublicKey
	{
		res, _, err := Base58CheckDecode(txnMeta.TransactorPublicKeyBase58Check)
		if err != nil {
			glog.Errorf("_getPublicKeysForTxn: Error decoding "+
				"TransactorPublicKeyBase58Check: %v %v",
				txnMeta.TransactorPublicKeyBase58Check, err)
		} else {
			publicKeys[MakePkMapKey(res)] = true
		}
	}

	// Add each AffectedPublicKey
	for _, affectedPk := range txnMeta.AffectedPublicKeys {
		res, _, err := Base58CheckDecode(affectedPk.PublicKeyBase58Check)
		if err != nil {
			glog.Errorf("_getPublicKeysForTxn: Error decoding AffectedPublicKey: %v %v %v",
				affectedPk.PublicKeyBase58Check, affectedPk.Metadata, err)
		} else {
			publicKeys[MakePkMapKey(res)] = true
		}
	}

	return publicKeys
}

func DbPutTxindexTransactionMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	desoTxn *MsgDeSoTxn, params *DeSoParams, txnMeta *TransactionMetadata) error {

	txID := desoTxn.Hash()

	if err := DbPutTxindexTransactionWithTxn(txn, snap, blockHeight, txID, txnMeta); err != nil {
		return fmt.Errorf("Problem adding txn to txindex transaction index: %v", err)
	}

	// Get the public keys involved with this transaction.
	publicKeys := _getPublicKeysForTxn(desoTxn, txnMeta, params)

	// For each public key found, add the txID from its list.
	for pkFoundIter := range publicKeys {
		pkFound := pkFoundIter

		// Simply add a new entry for each of the public keys found.
		if err := DbPutTxindexPublicKeyToTxnMappingSingleWithTxn(txn, snap, pkFound[:], txID); err != nil {
			return err
		}
	}

	// If we get here, it means everything went smoothly.
	return nil
}

func DbPutTxindexTransactionMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	desoTxn *MsgDeSoTxn, params *DeSoParams, txnMeta *TransactionMetadata) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutTxindexTransactionMappingsWithTxn(
			txn, snap, blockHeight, desoTxn, params, txnMeta)
	})
}

func DbDeleteTxindexTransactionMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	desoTxn *MsgDeSoTxn, params *DeSoParams) error {

	txID := desoTxn.Hash()

	// If the txnMeta isn't in the db then that's an error.
	txnMeta := DbGetTxindexTransactionRefByTxIDWithTxn(txn, snap, txID)
	if txnMeta == nil {
		return fmt.Errorf("DbDeleteTxindexTransactionMappingsWithTxn: Missing txnMeta for txID %v", txID)
	}

	// Get the public keys involved with this transaction.
	publicKeys := _getPublicKeysForTxn(desoTxn, txnMeta, params)

	// For each public key found, delete the txID mapping from the db.
	for pkFoundIter := range publicKeys {
		pkFound := pkFoundIter
		if err := DbDeleteTxindexPublicKeyToTxnMappingSingleWithTxn(txn, snap, pkFound[:], txID); err != nil {
			return err
		}
	}

	// Delete the metadata
	transactionIndexKey := DbTxindexTxIDKey(txID)
	if err := DBDeleteWithTxn(txn, snap, transactionIndexKey); err != nil {
		return fmt.Errorf("Problem deleting transaction index key: %v", err)
	}

	// If we get here, it means everything went smoothly.
	return nil
}

func DbDeleteTxindexTransactionMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	desoTxn *MsgDeSoTxn, params *DeSoParams) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteTxindexTransactionMappingsWithTxn(txn, snap, blockHeight, desoTxn, params)
	})
}

// DbGetTxindexFullTransactionByTxID
// TODO: This makes lookups inefficient when blocks are large. Shouldn't be a
// problem for a while, but keep an eye on it.
func DbGetTxindexFullTransactionByTxID(txindexDBHandle *badger.DB, snap *Snapshot,
	blockchainDBHandle *badger.DB, txID *BlockHash) (
	_txn *MsgDeSoTxn, _txnMeta *TransactionMetadata) {

	var txnFound *MsgDeSoTxn
	var txnMeta *TransactionMetadata
	err := txindexDBHandle.View(func(txn *badger.Txn) error {
		txnMeta = DbGetTxindexTransactionRefByTxIDWithTxn(txn, snap, txID)
		if txnMeta == nil {
			return fmt.Errorf("DbGetTxindexFullTransactionByTxID: Transaction not found")
		}
		blockHashBytes, err := hex.DecodeString(txnMeta.BlockHashHex)
		if err != nil {
			return fmt.Errorf("DbGetTxindexFullTransactionByTxID: Error parsing block "+
				"hash hex: %v %v", txnMeta.BlockHashHex, err)
		}
		blockHash := &BlockHash{}
		copy(blockHash[:], blockHashBytes)
		blockFound, err := GetBlock(blockHash, blockchainDBHandle, snap)
		if blockFound == nil || err != nil {
			return fmt.Errorf("DbGetTxindexFullTransactionByTxID: Block corresponding to txn not found")
		}

		txnFound = blockFound.Txns[txnMeta.TxnIndexInBlock]
		return nil
	})
	if err != nil {
		return nil, nil
	}

	return txnFound, txnMeta
}

// =======================================================================================
// DeSo app code start
// =======================================================================================

func _dbKeyForPostEntryHash(postHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPostHashToPostEntry...)
	key := append(prefixCopy, postHash[:]...)
	return key
}
func _dbKeyForPublicKeyPostHash(publicKey []byte, postHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, Prefixes.PrefixPosterPublicKeyPostHash...)
	key = append(key, publicKey...)
	key = append(key, postHash[:]...)
	return key
}
func _dbKeyForPosterPublicKeyTimestampPostHash(publicKey []byte, timestampNanos uint64, postHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, Prefixes.PrefixPosterPublicKeyTimestampPostHash...)
	key = append(key, publicKey...)
	key = append(key, EncodeUint64(timestampNanos)...)
	key = append(key, postHash[:]...)
	return key
}
func _dbKeyForTstampPostHash(tstampNanos uint64, postHash *BlockHash) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, Prefixes.PrefixTstampNanosPostHash...)
	key = append(key, EncodeUint64(tstampNanos)...)
	key = append(key, postHash[:]...)
	return key
}
func _dbKeyForCreatorBpsPostHash(creatorBps uint64, postHash *BlockHash) []byte {
	key := append([]byte{}, Prefixes.PrefixCreatorBpsPostHash...)
	key = append(key, EncodeUint64(creatorBps)...)
	key = append(key, postHash[:]...)
	return key
}
func _dbKeyForStakeMultipleBpsPostHash(stakeMultipleBps uint64, postHash *BlockHash) []byte {
	key := append([]byte{}, Prefixes.PrefixMultipleBpsPostHash...)
	key = append(key, EncodeUint64(stakeMultipleBps)...)
	key = append(key, postHash[:]...)
	return key
}
func _dbKeyForCommentParentStakeIDToPostHash(
	stakeID []byte, tstampNanos uint64, postHash *BlockHash) []byte {
	key := append([]byte{}, Prefixes.PrefixCommentParentStakeIDToPostHash...)
	key = append(key, stakeID[:]...)
	key = append(key, EncodeUint64(tstampNanos)...)
	key = append(key, postHash[:]...)
	return key
}

func DBGetPostEntryByPostHashWithTxn(txn *badger.Txn, snap *Snapshot,
	postHash *BlockHash) *PostEntry {

	key := _dbKeyForPostEntryHash(postHash)
	postEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	postEntryObj := &PostEntry{}
	rr := bytes.NewReader(postEntryBytes)
	DecodeFromBytes(postEntryObj, rr)
	return postEntryObj
}

func DBGetPostEntryByPostHash(db *badger.DB, snap *Snapshot, postHash *BlockHash) *PostEntry {
	var ret *PostEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetPostEntryByPostHashWithTxn(txn, snap, postHash)
		return nil
	})
	return ret
}

func DBDeletePostEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	postHash *BlockHash, params *DeSoParams) error {

	// First pull up the mapping that exists for the post hash passed in.
	// If one doesn't exist then there's nothing to do.
	postEntry := DBGetPostEntryByPostHashWithTxn(txn, snap, postHash)
	if postEntry == nil {
		return nil
	}

	// When a post exists, delete the mapping for the post.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForPostEntryHash(postHash)); err != nil {
		return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Deleting "+
			"post mapping for post hash %v", postHash)
	}

	// If the post is a comment we store it in a separate index. Comments are
	// technically posts but they really should be treated as their own entity.
	// The only reason they're not actually implemented that way is so that we
	// get code re-use.
	isComment := len(postEntry.ParentStakeID) == HashSizeBytes
	if isComment {
		// Extend the parent stake ID, which is a block hash, to 33 bytes, which
		// is the length of a public key and the standard length we use for this
		// key.
		extendedStakeID := append([]byte{}, postEntry.ParentStakeID...)
		extendedStakeID = append(extendedStakeID, 0x00)
		parentStakeIDKey := _dbKeyForCommentParentStakeIDToPostHash(
			extendedStakeID, postEntry.TimestampNanos, postEntry.PostHash)
		if err := DBDeleteWithTxn(txn, snap, parentStakeIDKey); err != nil {

			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Problem "+
				"deleting mapping for comment: %v: %v", postEntry, err)
		}
	} else {
		if err := DBDeleteWithTxn(txn, snap, _dbKeyForPosterPublicKeyTimestampPostHash(
			postEntry.PosterPublicKey, postEntry.TimestampNanos, postEntry.PostHash)); err != nil {

			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Deleting "+
				"public key mapping for post hash %v: %v", postHash, err)
		}
		if err := DBDeleteWithTxn(txn, snap, _dbKeyForTstampPostHash(
			postEntry.TimestampNanos, postEntry.PostHash)); err != nil {

			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Deleting "+
				"tstamp mapping for post hash %v: %v", postHash, err)
		}
		if err := DBDeleteWithTxn(txn, snap, _dbKeyForCreatorBpsPostHash(
			postEntry.CreatorBasisPoints, postEntry.PostHash)); err != nil {

			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Deleting "+
				"creatorBps mapping for post hash %v: %v", postHash, err)
		}
		if err := DBDeleteWithTxn(txn, snap, _dbKeyForStakeMultipleBpsPostHash(
			postEntry.StakeMultipleBasisPoints, postEntry.PostHash)); err != nil {

			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Deleting "+
				"stakeMultiple mapping for post hash %v: %v", postHash, err)
		}
	}

	// Delete the repost entries for the post.
	if IsVanillaRepost(postEntry) {
		if err := DBDeleteWithTxn(txn, snap,
			_dbKeyForReposterPubKeyRepostedPostHashToRepostPostHash(postEntry.PosterPublicKey, *postEntry.RepostedPostHash, *postEntry.PostHash)); err != nil {
			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Error problem deleting mapping for repostPostHash to ReposterPubKey: %v", err)
		}
		if err := DBDeleteWithTxn(txn, snap,
			_dbKeyForRepostedPostHashReposterPubKey(postEntry.RepostedPostHash, postEntry.PosterPublicKey)); err != nil {
			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Error problem adding "+
				"mapping for _dbKeyForRepostedPostHashReposterPubKey: %v", err)
		}
	} else if IsQuotedRepost(postEntry) {
		// Put quoted repost stuff.
		if err := DBDeleteWithTxn(txn, snap,
			_dbKeyForRepostedPostHashReposterPubKeyRepostPostHash(
				postEntry.RepostedPostHash, postEntry.PosterPublicKey, postEntry.PostHash)); err != nil {
			return errors.Wrapf(err, "DbDeletePostEntryMappingsWithTxn: Error problem adding "+
				"mapping for _dbKeyForRepostedPostHashReposterPubKeyRepostPostHash: %v", err)

		}
	}

	return nil
}

func DBDeletePostEntryMappings(handle *badger.DB, snap *Snapshot,
	postHash *BlockHash, params *DeSoParams) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeletePostEntryMappingsWithTxn(txn, snap, postHash, params)
	})
}

func DBPutPostEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	postEntry *PostEntry, params *DeSoParams) error {

	if err := DBSetWithTxn(txn, snap, _dbKeyForPostEntryHash(
		postEntry.PostHash), EncodeToBytes(blockHeight, postEntry)); err != nil {

		return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Problem "+
			"adding mapping for post: %v", postEntry.PostHash)
	}

	// If the post is a comment we store it in a separate index. Comments are
	// technically posts but they really should be treated as their own entity.
	// The only reason they're not actually implemented that way is so that we
	// get code re-use.
	isComment := len(postEntry.ParentStakeID) != 0
	if isComment {
		// Extend the parent stake ID, which is a block hash, to 33 bytes, which
		// is the length of a public key and the standard length we use for this
		// key.
		extendedStakeID := append([]byte{}, postEntry.ParentStakeID...)
		if len(extendedStakeID) == HashSizeBytes {
			extendedStakeID = append(extendedStakeID, 0x00)
		}
		if len(extendedStakeID) != btcec.PubKeyBytesLenCompressed {
			return fmt.Errorf("DbPutPostEntryMappingsWithTxn: extended "+
				"ParentStakeID %#v must have length %v",
				extendedStakeID, btcec.PubKeyBytesLenCompressed)
		}
		parentStakeIDKey := _dbKeyForCommentParentStakeIDToPostHash(
			extendedStakeID, postEntry.TimestampNanos, postEntry.PostHash)
		if err := DBSetWithTxn(txn, snap, parentStakeIDKey, []byte{}); err != nil {

			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Problem "+
				"adding mapping for comment: %v: %v", postEntry, err)
		}

	} else {
		if err := DBSetWithTxn(txn, snap, _dbKeyForPosterPublicKeyTimestampPostHash(
			postEntry.PosterPublicKey, postEntry.TimestampNanos, postEntry.PostHash), []byte{}); err != nil {

			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Problem "+
				"adding mapping for public key: %v: %v", postEntry, err)
		}
		if err := DBSetWithTxn(txn, snap, _dbKeyForTstampPostHash(
			postEntry.TimestampNanos, postEntry.PostHash), []byte{}); err != nil {

			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Problem "+
				"adding mapping for tstamp: %v", postEntry)
		}
		if err := DBSetWithTxn(txn, snap, _dbKeyForCreatorBpsPostHash(
			postEntry.CreatorBasisPoints, postEntry.PostHash), []byte{}); err != nil {

			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Problem "+
				"adding mapping for creatorBps: %v", postEntry)
		}
		if err := DBSetWithTxn(txn, snap, _dbKeyForStakeMultipleBpsPostHash(
			postEntry.StakeMultipleBasisPoints, postEntry.PostHash), []byte{}); err != nil {

			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Problem "+
				"adding mapping for stakeMultipleBps: %v", postEntry)
		}
	}
	// We treat reposting the same for both comments and posts.
	// We only store repost entry mappings for vanilla reposts
	if IsVanillaRepost(postEntry) {
		repostEntry := RepostEntry{
			RepostPostHash:   postEntry.PostHash,
			RepostedPostHash: postEntry.RepostedPostHash,
			ReposterPubKey:   postEntry.PosterPublicKey,
		}
		if err := DbPutRepostMappingsWithTxn(txn, snap, blockHeight, repostEntry); err != nil {
			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Error problem adding mapping for repostPostHash to ReposterPubKey: %v", err)
		}
		if err := DBSetWithTxn(txn, snap,
			_dbKeyForRepostedPostHashReposterPubKey(postEntry.RepostedPostHash, postEntry.PosterPublicKey),
			[]byte{}); err != nil {
			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Error problem adding "+
				"mapping for _dbKeyForRepostedPostHashReposterPubKey: %v", err)
		}
	} else if IsQuotedRepost(postEntry) {
		// Put quoted repost stuff.
		if err := DBSetWithTxn(txn, snap,
			_dbKeyForRepostedPostHashReposterPubKeyRepostPostHash(
				postEntry.RepostedPostHash, postEntry.PosterPublicKey, postEntry.PostHash),
			[]byte{}); err != nil {
			return errors.Wrapf(err, "DbPutPostEntryMappingsWithTxn: Error problem adding "+
				"mapping for _dbKeyForRepostedPostHashReposterPubKeyRepostPostHash: %v", err)
		}
	}
	return nil
}

func DBPutPostEntryMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	postEntry *PostEntry, params *DeSoParams) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutPostEntryMappingsWithTxn(txn, snap, blockHeight, postEntry, params)
	})
}

// Specifying minTimestampNanos gives you all posts after minTimestampNanos
// Pass minTimestampNanos = 0 && maxTimestampNanos = 0 if you want all posts
// Setting maxTimestampNanos = 0, will default maxTimestampNanos to the current time.
func DBGetAllPostsAndCommentsForPublicKeyOrderedByTimestamp(handle *badger.DB,
	snap *Snapshot, publicKey []byte, fetchEntries bool, minTimestampNanos uint64, maxTimestampNanos uint64) (
	_tstamps []uint64, _postAndCommentHashes []*BlockHash, _postAndCommentEntries []*PostEntry, _err error) {

	tstampsFetched := []uint64{}
	postAndCommentHashesFetched := []*BlockHash{}
	postAndCommentEntriesFetched := []*PostEntry{}
	dbPrefixx := append([]byte{}, Prefixes.PrefixPosterPublicKeyTimestampPostHash...)
	dbPrefixx = append(dbPrefixx, publicKey...)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		opts.PrefetchValues = false

		// Go in reverse order since a larger count is better.
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()
		// Since we iterate backwards, the prefix must be bigger than all possible
		// timestamps that could actually exist. We use eight bytes since the timestamp is
		// encoded as a 64-bit big-endian byte slice, which will be eight bytes long.
		maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		prefix := append(dbPrefixx, maxBigEndianUint64Bytes...)

		// If we have a maxTimeStamp, we use that instead of the maxBigEndianUint64.
		if maxTimestampNanos != 0 {
			prefix = append(dbPrefixx, EncodeUint64(maxTimestampNanos)...)
		}

		for it.Seek(prefix); it.ValidForPrefix(dbPrefixx); it.Next() {
			rawKey := it.Item().Key()

			// Key should be
			// [prefix][posterPublicKey][Timestamp][PostHash]

			// Pull out the relevant fields
			timestampSizeBytes := 8
			keyWithoutPrefix := rawKey[1:]
			//posterPublicKey := keyWithoutPrefix[:HashSizeBytes]
			publicKeySizeBytes := HashSizeBytes + 1
			tstampNanos := DecodeUint64(keyWithoutPrefix[publicKeySizeBytes:(publicKeySizeBytes + timestampSizeBytes)])

			postHash := &BlockHash{}
			copy(postHash[:], keyWithoutPrefix[(publicKeySizeBytes+timestampSizeBytes):])

			if tstampNanos < minTimestampNanos {
				break
			}

			tstampsFetched = append(tstampsFetched, tstampNanos)
			postAndCommentHashesFetched = append(postAndCommentHashesFetched, postHash)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	if !fetchEntries {
		return tstampsFetched, postAndCommentHashesFetched, nil, nil
	}

	for _, postHash := range postAndCommentHashesFetched {
		postEntry := DBGetPostEntryByPostHash(handle, snap, postHash)
		if postEntry == nil {
			return nil, nil, nil, fmt.Errorf("DBGetPostEntryByPostHash: "+
				"PostHash %v does not have corresponding entry", postHash)
		}
		postAndCommentEntriesFetched = append(postAndCommentEntriesFetched, postEntry)
	}

	return tstampsFetched, postAndCommentHashesFetched, postAndCommentEntriesFetched, nil
}

// DBGetAllPostsByTstamp returns all the posts in the db with the newest
// posts first.
//
// TODO(performance): This currently fetches all posts. We should implement
// some kind of pagination instead though.
func DBGetAllPostsByTstamp(handle *badger.DB, snap *Snapshot, fetchEntries bool) (
	_tstamps []uint64, _postHashes []*BlockHash, _postEntries []*PostEntry, _err error) {

	tstampsFetched := []uint64{}
	postHashesFetched := []*BlockHash{}
	postEntriesFetched := []*PostEntry{}
	dbPrefixx := append([]byte{}, Prefixes.PrefixTstampNanosPostHash...)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		opts.PrefetchValues = false

		// Go in reverse order since a larger count is better.
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()
		// Since we iterate backwards, the prefix must be bigger than all possible
		// timestamps that could actually exist. We use eight bytes since the timestamp is
		// encoded as a 64-bit big-endian byte slice, which will be eight bytes long.
		maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		prefix := append(dbPrefixx, maxBigEndianUint64Bytes...)
		for it.Seek(prefix); it.ValidForPrefix(dbPrefixx); it.Next() {
			rawKey := it.Item().Key()

			// Strip the prefix off the key and check its length. If it contains
			// a big-endian uint64 then it should be at least eight bytes.
			tstampPostHashKey := rawKey[1:]
			uint64BytesLen := len(maxBigEndianUint64Bytes)
			if len(tstampPostHashKey) != uint64BytesLen+HashSizeBytes {
				return fmt.Errorf("DBGetAllPostsByTstamp: Invalid key "+
					"length %d should be at least %d", len(tstampPostHashKey),
					uint64BytesLen+HashSizeBytes)
			}

			tstampNanos := DecodeUint64(tstampPostHashKey[:uint64BytesLen])

			// Appended to the tstamp should be the post hash so extract it here.
			postHash := &BlockHash{}
			copy(postHash[:], tstampPostHashKey[uint64BytesLen:])

			tstampsFetched = append(tstampsFetched, tstampNanos)
			postHashesFetched = append(postHashesFetched, postHash)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	if !fetchEntries {
		return tstampsFetched, postHashesFetched, nil, nil
	}

	for _, postHash := range postHashesFetched {
		postEntry := DBGetPostEntryByPostHash(handle, snap, postHash)
		if postEntry == nil {
			return nil, nil, nil, fmt.Errorf("DBGetPostEntryByPostHash: "+
				"PostHash %v does not have corresponding entry", postHash)
		}
		postEntriesFetched = append(postEntriesFetched, postEntry)
	}

	return tstampsFetched, postHashesFetched, postEntriesFetched, nil
}

// DBGetCommentPostHashesForParentStakeID returns all the comments, which are indexed by their
// stake ID rather than by their timestamp.
//
// TODO(performance): This currently fetches all comments. We should implement
// something where we only get the comments for particular posts instead.
func DBGetCommentPostHashesForParentStakeID(
	handle *badger.DB, snap *Snapshot, stakeIDXXX []byte, fetchEntries bool) (
	_tstamps []uint64, _commentPostHashes []*BlockHash, _commentPostEntryes []*PostEntry, _err error) {

	tstampsFetched := []uint64{}
	commentPostHashes := []*BlockHash{}
	commentEntriesFetched := []*PostEntry{}
	dbPrefixx := append([]byte{}, Prefixes.PrefixCommentParentStakeIDToPostHash...)
	dbPrefixx = append(dbPrefixx, stakeIDXXX...)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		opts.PrefetchValues = false

		it := txn.NewIterator(opts)
		defer it.Close()
		// Since we iterate backwards, the prefix must be bigger than all possible
		// counts that could actually exist. We use eight bytes since the count is
		// encoded as a 64-bit big-endian byte slice, which will be eight bytes long.
		maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		//prefix := append(dbPrefixx, maxBigEndianUint64Bytes...)
		prefix := dbPrefixx
		for it.Seek(prefix); it.ValidForPrefix(dbPrefixx); it.Next() {
			rawKey := it.Item().Key()

			// Strip the prefix off the key and check its length. It should contain
			// a 33-byte stake id, an 8 byte tstamp, and a 32 byte comment hash.
			stakeIDTstampPostHashKey := rawKey[1:]
			uint64BytesLen := len(maxBigEndianUint64Bytes)
			if len(stakeIDTstampPostHashKey) != btcec.PubKeyBytesLenCompressed+uint64BytesLen+HashSizeBytes {
				return fmt.Errorf("DBGetCommentPostHashesForParentStakeID: Invalid key "+
					"length %d should be at least %d", len(stakeIDTstampPostHashKey),
					btcec.PubKeyBytesLenCompressed+uint64BytesLen+HashSizeBytes)
			}

			//stakeID := stakeIDTstampPostHashKey[:btcec.PubKeyBytesLenCompressed]
			tstampNanos := DecodeUint64(stakeIDTstampPostHashKey[btcec.PubKeyBytesLenCompressed : btcec.PubKeyBytesLenCompressed+uint64BytesLen])

			commentPostHashBytes := stakeIDTstampPostHashKey[btcec.PubKeyBytesLenCompressed+uint64BytesLen:]
			commentPostHash := &BlockHash{}
			copy(commentPostHash[:], commentPostHashBytes)

			//stakeIDsFetched = append(stakeIDsFetched, stakeID)
			tstampsFetched = append(tstampsFetched, tstampNanos)
			commentPostHashes = append(commentPostHashes, commentPostHash)
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	if !fetchEntries {
		return tstampsFetched, commentPostHashes, nil, nil
	}

	for _, postHash := range commentPostHashes {
		postEntry := DBGetPostEntryByPostHash(handle, snap, postHash)
		if postEntry == nil {
			return nil, nil, nil, fmt.Errorf("DBGetCommentPostHashesForParentStakeID: "+
				"PostHash %v does not have corresponding entry", postHash)
		}
		commentEntriesFetched = append(commentEntriesFetched, postEntry)
	}

	return tstampsFetched, commentPostHashes, commentEntriesFetched, nil
}

// =======================================================================================
// NFTEntry db functions
// =======================================================================================
func _dbKeyForNFTPostHashSerialNumber(nftPostHash *BlockHash, serialNumber uint64) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPostHashSerialNumberToNFTEntry...)
	key := append(prefixCopy, nftPostHash[:]...)
	key = append(key, EncodeUint64(serialNumber)...)
	return key
}

func _dbKeyForPKIDIsForSaleBidAmountNanosNFTPostHashSerialNumber(pkid *PKID, isForSale bool, bidAmountNanos uint64, nftPostHash *BlockHash, serialNumber uint64) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixPKIDIsForSaleBidAmountNanosPostHashSerialNumberToNFTEntry...)
	key := append(prefixCopy, pkid[:]...)
	key = append(key, BoolToByte(isForSale))
	key = append(key, EncodeUint64(bidAmountNanos)...)
	key = append(key, nftPostHash[:]...)
	key = append(key, EncodeUint64(serialNumber)...)
	return key
}

func DBGetNFTEntryByPostHashSerialNumberWithTxn(txn *badger.Txn, snap *Snapshot,
	postHash *BlockHash, serialNumber uint64) *NFTEntry {

	key := _dbKeyForNFTPostHashSerialNumber(postHash, serialNumber)
	nftEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	nftEntryObj := &NFTEntry{}
	rr := bytes.NewReader(nftEntryBytes)
	DecodeFromBytes(nftEntryObj, rr)
	return nftEntryObj
}

func DBGetNFTEntryByPostHashSerialNumber(db *badger.DB, snap *Snapshot,
	postHash *BlockHash, serialNumber uint64) *NFTEntry {

	var ret *NFTEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetNFTEntryByPostHashSerialNumberWithTxn(txn, snap, postHash, serialNumber)
		return nil
	})
	return ret
}

func DBDeleteNFTMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	nftPostHash *BlockHash, serialNumber uint64) error {

	// First pull up the mapping that exists for the post / serial # passed in.
	// If one doesn't exist then there's nothing to do.
	nftEntry := DBGetNFTEntryByPostHashSerialNumberWithTxn(txn, snap, nftPostHash, serialNumber)
	if nftEntry == nil {
		return nil
	}

	// When an nftEntry exists, delete the mapping.
	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForPKIDIsForSaleBidAmountNanosNFTPostHashSerialNumber(
			nftEntry.OwnerPKID, nftEntry.IsForSale, nftEntry.LastAcceptedBidAmountNanos, nftPostHash, serialNumber)); err != nil {
		return errors.Wrapf(err, "DbDeleteNFTMappingsWithTxn: Deleting "+
			"nft mapping for pkid %v post hash %v serial number %d", nftEntry.OwnerPKID, nftPostHash, serialNumber)
	}

	// When an nftEntry exists, delete the mapping.
	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForNFTPostHashSerialNumber(nftPostHash, serialNumber)); err != nil {
		return errors.Wrapf(err, "DbDeleteNFTMappingsWithTxn: Deleting "+
			"nft mapping for post hash %v serial number %d", nftPostHash, serialNumber)
	}

	return nil
}

func DBDeleteNFTMappings(
	handle *badger.DB, snap *Snapshot, postHash *BlockHash, serialNumber uint64) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteNFTMappingsWithTxn(txn, snap, postHash, serialNumber)
	})
}

func DBPutNFTEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64, nftEntry *NFTEntry) error {
	nftEntryBytes := EncodeToBytes(blockHeight, nftEntry)

	if err := DBSetWithTxn(txn, snap, _dbKeyForNFTPostHashSerialNumber(
		nftEntry.NFTPostHash, nftEntry.SerialNumber), nftEntryBytes); err != nil {

		return errors.Wrapf(err, "DbPutNFTEntryMappingsWithTxn: Problem "+
			"adding mapping for post: %v, serial number: %d", nftEntry.NFTPostHash, nftEntry.SerialNumber)
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForPKIDIsForSaleBidAmountNanosNFTPostHashSerialNumber(
		nftEntry.OwnerPKID, nftEntry.IsForSale, nftEntry.LastAcceptedBidAmountNanos, nftEntry.NFTPostHash, nftEntry.SerialNumber), nftEntryBytes); err != nil {
		return errors.Wrapf(err, "DbPutNFTEntryMappingsWithTxn: Problem "+
			"adding mapping for pkid: %v, post: %v, serial number: %d", nftEntry.OwnerPKID, nftEntry.NFTPostHash, nftEntry.SerialNumber)
	}

	return nil
}

func DBPutNFTEntryMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64, nftEntry *NFTEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutNFTEntryMappingsWithTxn(txn, snap, blockHeight, nftEntry)
	})
}

// DBGetNFTEntriesForPostHash gets NFT Entries *from the DB*. Does not include mempool txns.
func DBGetNFTEntriesForPostHash(handle *badger.DB, nftPostHash *BlockHash) (_nftEntries []*NFTEntry) {
	nftEntries := []*NFTEntry{}
	prefix := append([]byte{}, Prefixes.PrefixPostHashSerialNumberToNFTEntry...)
	keyPrefix := append(prefix, nftPostHash[:]...)
	_, entryByteStringsFound := _enumerateKeysForPrefix(handle, keyPrefix)
	for _, byteString := range entryByteStringsFound {
		currentEntry := &NFTEntry{}
		rr := bytes.NewReader(byteString)
		DecodeFromBytes(currentEntry, rr)
		nftEntries = append(nftEntries, currentEntry)
	}
	return nftEntries
}

// =======================================================================================
// NFTOwnership db functions
// NOTE: This index is not essential to running the protocol and should be computed
// outside of the protocol layer once update to the creation of TxIndex are complete.
// =======================================================================================

func DBGetNFTEntryByNFTOwnershipDetailsWithTxn(txn *badger.Txn, snap *Snapshot, ownerPKID *PKID,
	isForSale bool, bidAmountNanos uint64, postHash *BlockHash, serialNumber uint64) *NFTEntry {

	key := _dbKeyForPKIDIsForSaleBidAmountNanosNFTPostHashSerialNumber(ownerPKID, isForSale, bidAmountNanos, postHash, serialNumber)
	nftEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	nftEntryObj := &NFTEntry{}
	rr := bytes.NewReader(nftEntryBytes)
	DecodeFromBytes(nftEntryObj, rr)
	return nftEntryObj
}

func DBGetNFTEntryByNFTOwnershipDetails(db *badger.DB, snap *Snapshot, ownerPKID *PKID,
	isForSale bool, bidAmountNanos uint64, postHash *BlockHash, serialNumber uint64) *NFTEntry {

	var ret *NFTEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetNFTEntryByNFTOwnershipDetailsWithTxn(txn, snap, ownerPKID, isForSale, bidAmountNanos, postHash, serialNumber)
		return nil
	})
	return ret
}

// DBGetNFTEntriesForPKID gets NFT Entries *from the DB*. Does not include mempool txns.
func DBGetNFTEntriesForPKID(handle *badger.DB, ownerPKID *PKID) (_nftEntries []*NFTEntry) {
	var nftEntries []*NFTEntry
	prefix := append([]byte{}, Prefixes.PrefixPKIDIsForSaleBidAmountNanosPostHashSerialNumberToNFTEntry...)
	keyPrefix := append(prefix, ownerPKID[:]...)
	_, entryByteStringsFound := _enumerateKeysForPrefix(handle, keyPrefix)
	for _, byteString := range entryByteStringsFound {
		currentEntry := &NFTEntry{}
		rr := bytes.NewReader(byteString)
		DecodeFromBytes(currentEntry, rr)
		nftEntries = append(nftEntries, currentEntry)
	}
	return nftEntries
}

// =======================================================================================
// AcceptedNFTBidEntries db functions
// NOTE: This index is not essential to running the protocol and should be computed
// outside of the protocol layer once update to the creation of TxIndex are complete.
// =======================================================================================
func _dbKeyForPostHashSerialNumberToAcceptedBidEntries(nftPostHash *BlockHash, serialNumber uint64) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixPostHashSerialNumberToAcceptedBidEntries...)
	key := append(prefixCopy, nftPostHash[:]...)
	key = append(key, EncodeUint64(serialNumber)...)
	return key
}

// TODO: are we sure we want to pass a pointer to an array here?
func DBPutAcceptedNFTBidEntriesMappingWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	nftKey NFTKey, nftBidEntries *[]*NFTBidEntry) error {

	nftBidEntryBundle := &NFTBidEntryBundle{
		nftBidEntryBundle: *nftBidEntries,
	}
	if err := DBSetWithTxn(txn, snap, _dbKeyForPostHashSerialNumberToAcceptedBidEntries(
		&nftKey.NFTPostHash, nftKey.SerialNumber), EncodeToBytes(blockHeight, nftBidEntryBundle)); err != nil {

		return errors.Wrapf(err, "DBPutAcceptedNFTBidEntriesMappingWithTxn: Problem "+
			"adding accepted bid mapping for post: %v, serial number: %d", nftKey.NFTPostHash, nftKey.SerialNumber)
	}
	return nil
}

func DBPutAcceptedNFTBidEntriesMapping(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	nftKey NFTKey, nftBidEntries *[]*NFTBidEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutAcceptedNFTBidEntriesMappingWithTxn(txn, snap, blockHeight, nftKey, nftBidEntries)
	})
}

func DBGetAcceptedNFTBidEntriesByPostHashSerialNumberWithTxn(txn *badger.Txn, snap *Snapshot,
	postHash *BlockHash, serialNumber uint64) *[]*NFTBidEntry {

	key := _dbKeyForPostHashSerialNumberToAcceptedBidEntries(postHash, serialNumber)
	nftBidEntriesBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	nftBidEntriesBundle := &NFTBidEntryBundle{}
	rr := bytes.NewReader(nftBidEntriesBytes)
	if exists, err := DecodeFromBytes(nftBidEntriesBundle, rr); !exists || err != nil {
		glog.Errorf("DBGetAcceptedNFTBidEntriesByPostHashSerialNumberWithTxn: Problem reading NFTBidEntryBundle, error: (%v)", err)
		return nil
	}
	return &nftBidEntriesBundle.nftBidEntryBundle
}

func DBGetAcceptedNFTBidEntriesByPostHashSerialNumber(db *badger.DB, snap *Snapshot,
	postHash *BlockHash, serialNumber uint64) *[]*NFTBidEntry {

	var ret *[]*NFTBidEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetAcceptedNFTBidEntriesByPostHashSerialNumberWithTxn(txn, snap, postHash, serialNumber)
		return nil
	})
	return ret
}

func DBDeleteAcceptedNFTBidEntriesMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	nftPostHash *BlockHash, serialNumber uint64) error {

	// First check to see if there is an existing mapping. If one doesn't exist, there's nothing to do.
	nftBidEntries := DBGetAcceptedNFTBidEntriesByPostHashSerialNumberWithTxn(txn, snap, nftPostHash, serialNumber)
	if nftBidEntries == nil {
		return nil
	}

	// When an nftEntry exists, delete both mapping.
	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForPostHashSerialNumberToAcceptedBidEntries(nftPostHash, serialNumber)); err != nil {
		return errors.Wrapf(err, "DBDeleteAcceptedNFTBidEntriesMappingsWithTxn: Deleting "+
			"accepted nft bid mapping for post hash %v serial number %d", nftPostHash, serialNumber)
	}

	return nil
}

func DBDeleteAcceptedNFTBidMappings(handle *badger.DB, snap *Snapshot,
	postHash *BlockHash, serialNumber uint64) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteAcceptedNFTBidEntriesMappingsWithTxn(txn, snap, postHash, serialNumber)
	})
}

// =======================================================================================
// NFTBidEntry db functions
// =======================================================================================

func _dbKeyForNFTPostHashSerialNumberBidNanosBidderPKID(bidEntry *NFTBidEntry) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPostHashSerialNumberBidNanosBidderPKID...)
	key := append(prefixCopy, bidEntry.NFTPostHash[:]...)
	key = append(key, EncodeUint64(bidEntry.SerialNumber)...)
	key = append(key, EncodeUint64(bidEntry.BidAmountNanos)...)
	key = append(key, bidEntry.BidderPKID[:]...)
	return key
}

func _dbKeyForNFTBidderPKIDPostHashSerialNumber(
	bidderPKID *PKID, nftPostHash *BlockHash, serialNumber uint64) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixBidderPKIDPostHashSerialNumberToBidNanos...)
	key := append(prefixCopy, bidderPKID[:]...)
	key = append(key, nftPostHash[:]...)
	key = append(key, EncodeUint64(serialNumber)...)
	return key
}

func _dbSeekKeyForNFTBids(nftHash *BlockHash, serialNumber uint64) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixPostHashSerialNumberBidNanosBidderPKID...)
	key := append(prefixCopy, nftHash[:]...)
	key = append(key, EncodeUint64(serialNumber)...)
	return key
}

func DBGetNFTBidEntryForNFTBidKeyWithTxn(txn *badger.Txn, snap *Snapshot,
	nftBidKey *NFTBidKey) *NFTBidEntry {

	key := _dbKeyForNFTBidderPKIDPostHashSerialNumber(
		&nftBidKey.BidderPKID, &nftBidKey.NFTPostHash, nftBidKey.SerialNumber)

	nftBidBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	// If we get here then it means we actually had a bid amount for this key in the DB.
	nftBidAmountNanos := DecodeUint64(nftBidBytes)

	nftBidEntry := &NFTBidEntry{
		BidderPKID:     &nftBidKey.BidderPKID,
		NFTPostHash:    &nftBidKey.NFTPostHash,
		SerialNumber:   nftBidKey.SerialNumber,
		BidAmountNanos: nftBidAmountNanos,
	}

	return nftBidEntry
}

func DBGetNFTBidEntryForNFTBidKey(db *badger.DB, snap *Snapshot, nftBidKey *NFTBidKey) *NFTBidEntry {
	var ret *NFTBidEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetNFTBidEntryForNFTBidKeyWithTxn(txn, snap, nftBidKey)
		return nil
	})
	return ret
}

func DBDeleteNFTBidMappingsWithTxn(txn *badger.Txn, snap *Snapshot, nftBidKey *NFTBidKey) error {

	// First check to see if there is an existing mapping. If one doesn't exist, there's nothing to do.
	nftBidEntry := DBGetNFTBidEntryForNFTBidKeyWithTxn(txn, snap, nftBidKey)
	if nftBidEntry == nil {
		return nil
	}

	// When an nftEntry exists, delete both mapping.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForNFTPostHashSerialNumberBidNanosBidderPKID(nftBidEntry)); err != nil {
		return errors.Wrapf(err, "DbDeleteNFTBidMappingsWithTxn: Deleting "+
			"nft bid mapping for nftBidKey %v", nftBidKey)
	}

	// When an nftEntry exists, delete both mapping.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForNFTBidderPKIDPostHashSerialNumber(
		nftBidEntry.BidderPKID, nftBidEntry.NFTPostHash, nftBidEntry.SerialNumber)); err != nil {
		return errors.Wrapf(err, "DbDeleteNFTBidMappingsWithTxn: Deleting "+
			"nft bid mapping for nftBidKey %v", nftBidKey)
	}

	return nil
}

func DBDeleteNFTBidMappings(handle *badger.DB, snap *Snapshot, nftBidKey *NFTBidKey) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteNFTBidMappingsWithTxn(txn, snap, nftBidKey)
	})
}

func DBPutNFTBidEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot, nftBidEntry *NFTBidEntry) error {
	// We store two indexes for NFT bids. (1) sorted by bid amount nanos in the key and
	// (2) sorted by the bidder PKID. Both come in handy.

	// Put the first index --> []byte{} (no data needs to be stored since it all info is in the key)
	if err := DBSetWithTxn(txn, snap,
		_dbKeyForNFTPostHashSerialNumberBidNanosBidderPKID(nftBidEntry), []byte{}); err != nil {

		return errors.Wrapf(err, "DbPutNFTBidEntryMappingsWithTxn: Problem "+
			"adding mapping to BidderPKID for bid entry: %v", nftBidEntry)
	}

	// Put the second index --> BidAmountNanos
	if err := DBSetWithTxn(txn, snap, _dbKeyForNFTBidderPKIDPostHashSerialNumber(
		nftBidEntry.BidderPKID, nftBidEntry.NFTPostHash, nftBidEntry.SerialNumber,
	), EncodeUint64(nftBidEntry.BidAmountNanos)); err != nil {

		return errors.Wrapf(err, "DbPutNFTBidEntryMappingsWithTxn: Problem "+
			"adding mapping to BidAmountNanos for bid entry: %v", nftBidEntry)
	}

	return nil
}

func DBPutNFTBidEntryMappings(handle *badger.DB, snap *Snapshot, nftEntry *NFTBidEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutNFTBidEntryMappingsWithTxn(txn, snap, nftEntry)
	})
}

func DBGetNFTBidEntriesForPKID(handle *badger.DB, bidderPKID *PKID) (_nftBidEntries []*NFTBidEntry) {
	nftBidEntries := []*NFTBidEntry{}
	{
		prefix := append([]byte{}, Prefixes.PrefixBidderPKIDPostHashSerialNumberToBidNanos...)
		keyPrefix := append(prefix, bidderPKID[:]...)
		keysFound, valuesFound := _enumerateKeysForPrefix(handle, keyPrefix)
		bidderPKIDLength := len(bidderPKID[:])
		for ii, keyFound := range keysFound {

			postHashStartIdx := 1 + bidderPKIDLength           // The length of prefix + length of PKID
			postHashEndIdx := postHashStartIdx + HashSizeBytes // Add the length of the bid amount (uint64).

			// Cut the bid amount out of the key and decode.
			postHashBytes := keyFound[postHashStartIdx:postHashEndIdx]

			nftHash := &BlockHash{}
			copy(nftHash[:], postHashBytes)

			serialNumber := DecodeUint64(keyFound[postHashEndIdx:])

			bidAmountNanos := DecodeUint64(valuesFound[ii])

			currentEntry := &NFTBidEntry{
				NFTPostHash:    nftHash,
				SerialNumber:   serialNumber,
				BidderPKID:     bidderPKID,
				BidAmountNanos: bidAmountNanos,
			}
			nftBidEntries = append(nftBidEntries, currentEntry)
		}
	}
	return nftBidEntries
}

// Get NFT bid Entries *from the DB*. Does not include mempool txns.
func DBGetNFTBidEntries(handle *badger.DB, nftPostHash *BlockHash, serialNumber uint64,
) (_nftBidEntries []*NFTBidEntry) {
	nftBidEntries := []*NFTBidEntry{}
	{
		prefix := append([]byte{}, Prefixes.PrefixPostHashSerialNumberBidNanosBidderPKID...)
		keyPrefix := append(prefix, nftPostHash[:]...)
		keyPrefix = append(keyPrefix, EncodeUint64(serialNumber)...)
		keysFound, _ := _enumerateKeysForPrefix(handle, keyPrefix)
		for _, keyFound := range keysFound {
			bidAmountStartIdx := 1 + HashSizeBytes + 8 // The length of prefix + the post hash + the serial #.
			bidAmountEndIdx := bidAmountStartIdx + 8   // Add the length of the bid amount (uint64).

			// Cut the bid amount out of the key and decode.
			bidAmountBytes := keyFound[bidAmountStartIdx:bidAmountEndIdx]
			bidAmountNanos := DecodeUint64(bidAmountBytes)

			// Cut the pkid bytes out of the keys
			bidderPKIDBytes := keyFound[bidAmountEndIdx:]

			// Construct the bidder PKID.
			bidderPKID := PublicKeyToPKID(bidderPKIDBytes)

			currentEntry := &NFTBidEntry{
				NFTPostHash:    nftPostHash,
				SerialNumber:   serialNumber,
				BidderPKID:     bidderPKID,
				BidAmountNanos: bidAmountNanos,
			}
			nftBidEntries = append(nftBidEntries, currentEntry)
		}
	}
	return nftBidEntries
}

func DBGetNFTBidEntriesPaginated(
	handle *badger.DB,
	nftHash *BlockHash,
	serialNumber uint64,
	startEntry *NFTBidEntry,
	limit int,
	reverse bool,
) (_bidEntries []*NFTBidEntry) {
	seekKey := _dbSeekKeyForNFTBids(nftHash, serialNumber)
	startKey := seekKey
	if startEntry != nil {
		startKey = _dbKeyForNFTPostHashSerialNumberBidNanosBidderPKID(startEntry)
	}
	// The key length consists of: (1 prefix byte) + (BlockHash) + (2 x uint64) + (PKID)
	maxKeyLen := 1 + HashSizeBytes + 16 + btcec.PubKeyBytesLenCompressed
	keysBytes, _, _ := DBGetPaginatedKeysAndValuesForPrefix(
		handle,
		startKey,
		seekKey,
		maxKeyLen,
		limit,
		reverse,
		false)
	// TODO: We should probably handle the err case for this function.

	// Chop up the keyBytes into bid entries.
	var bidEntries []*NFTBidEntry
	for _, keyBytes := range keysBytes {
		serialNumStartIdx := 1 + HashSizeBytes
		bidAmountStartIdx := serialNumStartIdx + 8
		bidderPKIDStartIdx := bidAmountStartIdx + 8

		nftHashBytes := keyBytes[1:serialNumStartIdx]
		serialNumberBytes := keyBytes[serialNumStartIdx:bidAmountStartIdx]
		bidAmountBytes := keyBytes[bidAmountStartIdx:bidderPKIDStartIdx]
		bidderPKIDBytes := keyBytes[bidderPKIDStartIdx:]

		nftHash := &BlockHash{}
		copy(nftHash[:], nftHashBytes)
		serialNumber := DecodeUint64(serialNumberBytes)
		bidAmount := DecodeUint64(bidAmountBytes)
		bidderPKID := &PKID{}
		copy(bidderPKID[:], bidderPKIDBytes)

		bidEntry := &NFTBidEntry{
			NFTPostHash:    nftHash,
			SerialNumber:   serialNumber,
			BidAmountNanos: bidAmount,
			BidderPKID:     bidderPKID,
		}

		bidEntries = append(bidEntries, bidEntry)
	}

	return bidEntries
}

// ======================================================================================
// Authorize derived key functions
//  	<prefix_id, owner pub key [33]byte, derived pub key [33]byte> -> <DerivedKeyEntry>
// ======================================================================================

func _dbKeyForOwnerToDerivedKeyMapping(
	ownerPublicKey PublicKey, derivedPublicKey PublicKey) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixAuthorizeDerivedKey...)
	key := append(prefixCopy, ownerPublicKey[:]...)
	key = append(key, derivedPublicKey[:]...)
	return key
}

func _dbSeekPrefixForDerivedKeyMappings(
	ownerPublicKey PublicKey) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixAuthorizeDerivedKey...)
	key := append(prefixCopy, ownerPublicKey[:]...)
	return key
}

func DBPutDerivedKeyMappingWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	ownerPublicKey PublicKey, derivedPublicKey PublicKey, derivedKeyEntry *DerivedKeyEntry) error {

	key := _dbKeyForOwnerToDerivedKeyMapping(ownerPublicKey, derivedPublicKey)

	return DBSetWithTxn(txn, snap, key, EncodeToBytes(blockHeight, derivedKeyEntry))
}

func DBPutDerivedKeyMapping(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	ownerPublicKey PublicKey, derivedPublicKey PublicKey, derivedKeyEntry *DerivedKeyEntry) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutDerivedKeyMappingWithTxn(txn, snap, blockHeight, ownerPublicKey, derivedPublicKey, derivedKeyEntry)
	})
}

func DBGetOwnerToDerivedKeyMappingWithTxn(txn *badger.Txn, snap *Snapshot,
	ownerPublicKey PublicKey, derivedPublicKey PublicKey) *DerivedKeyEntry {

	key := _dbKeyForOwnerToDerivedKeyMapping(ownerPublicKey, derivedPublicKey)
	derivedKeyBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	derivedKeyEntry := &DerivedKeyEntry{}
	rr := bytes.NewReader(derivedKeyBytes)
	DecodeFromBytes(derivedKeyEntry, rr)
	return derivedKeyEntry
}

func DBGetOwnerToDerivedKeyMapping(db *badger.DB, snap *Snapshot,
	ownerPublicKey PublicKey, derivedPublicKey PublicKey) *DerivedKeyEntry {

	var derivedKeyEntry *DerivedKeyEntry
	db.View(func(txn *badger.Txn) error {
		derivedKeyEntry = DBGetOwnerToDerivedKeyMappingWithTxn(txn, snap, ownerPublicKey, derivedPublicKey)
		return nil
	})
	return derivedKeyEntry
}

func DBDeleteDerivedKeyMappingWithTxn(txn *badger.Txn, snap *Snapshot,
	ownerPublicKey PublicKey, derivedPublicKey PublicKey) error {

	// When a mapping exists, delete it.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForOwnerToDerivedKeyMapping(ownerPublicKey, derivedPublicKey)); err != nil {
		return errors.Wrapf(err, "DBDeleteDerivedKeyMappingWithTxn: Deleting "+
			"ownerPublicKey %s and derivedPublicKey %s failed",
			PkToStringMainnet(ownerPublicKey[:]), PkToStringMainnet(derivedPublicKey[:]))
	}

	return nil
}

func DBDeleteDerivedKeyMapping(handle *badger.DB, snap *Snapshot,
	ownerPublicKey PublicKey, derivedPublicKey PublicKey) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteDerivedKeyMappingWithTxn(txn, snap, ownerPublicKey, derivedPublicKey)
	})
}

func DBGetAllOwnerToDerivedKeyMappings(handle *badger.DB, ownerPublicKey PublicKey) (
	_entries []*DerivedKeyEntry, _err error) {

	prefix := _dbSeekPrefixForDerivedKeyMappings(ownerPublicKey)
	_, valsFound := _enumerateKeysForPrefix(handle, prefix)

	var derivedEntries []*DerivedKeyEntry
	for _, keyBytes := range valsFound {
		derivedKeyEntry := &DerivedKeyEntry{}
		rr := bytes.NewReader(keyBytes)
		DecodeFromBytes(derivedKeyEntry, rr)
		derivedEntries = append(derivedEntries, derivedKeyEntry)
	}

	return derivedEntries, nil
}

// ======================================================================================
// Profile code
// ======================================================================================
func _dbKeyForPKIDToProfileEntry(pkid *PKID) []byte {
	prefixCopy := append([]byte{}, Prefixes.PrefixPKIDToProfileEntry...)
	key := append(prefixCopy, pkid[:]...)
	return key
}
func _dbKeyForProfileUsernameToPKID(nonLowercaseUsername []byte) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	key := append([]byte{}, Prefixes.PrefixProfileUsernameToPKID...)
	// Always lowercase the username when we use it as a key in our db. This allows
	// us to check uniqueness in a case-insensitive way.
	lowercaseUsername := []byte(strings.ToLower(string(nonLowercaseUsername)))
	key = append(key, lowercaseUsername...)
	return key
}

// This is the key we use to sort profiles by their amount of DeSo locked
func _dbKeyForCreatorDeSoLockedNanosCreatorPKID(desoLockedNanos uint64, pkid *PKID) []byte {
	key := append([]byte{}, Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID...)
	key = append(key, EncodeUint64(desoLockedNanos)...)
	key = append(key, pkid[:]...)
	return key
}

func DbPrefixForCreatorDeSoLockedNanosCreatorPKID() []byte {
	return append([]byte{}, Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID...)
}

func DBGetPKIDForUsernameWithTxn(txn *badger.Txn,
	snap *Snapshot, username []byte) *PKID {

	key := _dbKeyForProfileUsernameToPKID(username)
	profileBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	return PublicKeyToPKID(profileBytes)
}

func DBGetPKIDForUsername(db *badger.DB, snap *Snapshot, username []byte) *PKID {
	var ret *PKID
	db.View(func(txn *badger.Txn) error {
		ret = DBGetPKIDForUsernameWithTxn(txn, snap, username)
		return nil
	})
	return ret
}

func DBGetProfileEntryForUsernameWithTxn(txn *badger.Txn,
	snap *Snapshot, username []byte) *ProfileEntry {

	pkid := DBGetPKIDForUsernameWithTxn(txn, snap, username)
	if pkid == nil {
		return nil
	}

	return DBGetProfileEntryForPKIDWithTxn(txn, snap, pkid)
}

func DBGetProfileEntryForUsername(db *badger.DB, snap *Snapshot, username []byte) *ProfileEntry {
	var ret *ProfileEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetProfileEntryForUsernameWithTxn(txn, snap, username)
		return nil
	})
	return ret
}

func DBGetProfileEntryForPKIDWithTxn(txn *badger.Txn, snap *Snapshot,
	pkid *PKID) *ProfileEntry {

	key := _dbKeyForPKIDToProfileEntry(pkid)
	profileEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}

	profileEntryObj := &ProfileEntry{}
	rr := bytes.NewReader(profileEntryBytes)
	DecodeFromBytes(profileEntryObj, rr)
	return profileEntryObj
}

func DBGetProfileEntryForPKID(db *badger.DB, snap *Snapshot, pkid *PKID) *ProfileEntry {
	var ret *ProfileEntry
	db.View(func(txn *badger.Txn) error {
		ret = DBGetProfileEntryForPKIDWithTxn(txn, snap, pkid)
		return nil
	})
	return ret
}

func DBDeleteProfileEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	pkid *PKID, params *DeSoParams) error {

	// First pull up the mapping that exists for the profile pub key passed in.
	// If one doesn't exist then there's nothing to do.
	profileEntry := DBGetProfileEntryForPKIDWithTxn(txn, snap, pkid)
	if profileEntry == nil {
		return nil
	}

	// When a profile exists, delete the pkid mapping for the profile.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForPKIDToProfileEntry(pkid)); err != nil {
		return errors.Wrapf(err, "DbDeleteProfileEntryMappingsWithTxn: Deleting "+
			"profile mapping for profile PKID: %v",
			PkToString(pkid[:], params))
	}

	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForProfileUsernameToPKID(profileEntry.Username)); err != nil {

		return errors.Wrapf(err, "DbDeleteProfileEntryMappingsWithTxn: Deleting "+
			"username mapping for profile username %v", string(profileEntry.Username))
	}

	// The coin deso mapping
	if err := DBDeleteWithTxn(txn, snap,
		_dbKeyForCreatorDeSoLockedNanosCreatorPKID(
			profileEntry.CreatorCoinEntry.DeSoLockedNanos, pkid)); err != nil {

		return errors.Wrapf(err, "DbDeleteProfileEntryMappingsWithTxn: Deleting "+
			"coin mapping for profile username %v", string(profileEntry.Username))
	}

	return nil
}

func DBPutProfileEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	profileEntry *ProfileEntry, pkid *PKID, params *DeSoParams) error {

	// Set the main PKID -> profile entry mapping.
	if err := DBSetWithTxn(txn, snap, _dbKeyForPKIDToProfileEntry(pkid),
		EncodeToBytes(blockHeight, profileEntry)); err != nil {

		return errors.Wrapf(err, "DbPutProfileEntryMappingsWithTxn: Problem "+
			"adding mapping for profile: %v", PkToString(pkid[:], params))
	}

	// Username
	if err := DBSetWithTxn(txn, snap,
		_dbKeyForProfileUsernameToPKID(profileEntry.Username),
		pkid[:]); err != nil {

		return errors.Wrapf(err, "DbPutProfileEntryMappingsWithTxn: Problem "+
			"adding mapping for profile with username: %v", string(profileEntry.Username))
	}

	// The coin deso mapping
	if err := DBSetWithTxn(txn, snap,
		_dbKeyForCreatorDeSoLockedNanosCreatorPKID(
			profileEntry.CreatorCoinEntry.DeSoLockedNanos, pkid), []byte{}); err != nil {

		return errors.Wrapf(err, "DbPutProfileEntryMappingsWithTxn: Problem "+
			"adding mapping for profile coin: ")
	}

	return nil
}

func DBPutProfileEntryMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	profileEntry *ProfileEntry, pkid *PKID, params *DeSoParams) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutProfileEntryMappingsWithTxn(txn, snap, blockHeight, profileEntry, pkid, params)
	})
}

// DBGetAllProfilesByCoinValue returns all the profiles in the db with the
// highest coin values first.
//
// TODO(performance): This currently fetches all profiles. We should implement
// some kind of pagination instead though.
func DBGetAllProfilesByCoinValue(handle *badger.DB, snap *Snapshot, fetchEntries bool) (
	_lockedDeSoNanos []uint64, _profilePKIDs []*PKID,
	_profileEntries []*ProfileEntry, _err error) {

	lockedDeSoNanosFetched := []uint64{}
	profilePublicKeysFetched := []*PKID{}
	profileEntriesFetched := []*ProfileEntry{}
	dbPrefixx := append([]byte{}, Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID...)

	err := handle.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions

		opts.PrefetchValues = false

		// Go in reverse order since a larger count is better.
		opts.Reverse = true

		it := txn.NewIterator(opts)
		defer it.Close()
		// Since we iterate backwards, the prefix must be bigger than all possible
		// counts that could actually exist. We use eight bytes since the count is
		// encoded as a 64-bit big-endian byte slice, which will be eight bytes long.
		maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		prefix := append(dbPrefixx, maxBigEndianUint64Bytes...)
		for it.Seek(prefix); it.ValidForPrefix(dbPrefixx); it.Next() {
			rawKey := it.Item().Key()

			// Strip the prefix off the key and check its length. If it contains
			// a big-endian uint64 then it should be at least eight bytes.
			lockedDeSoPubKeyConcatKey := rawKey[1:]
			uint64BytesLen := len(maxBigEndianUint64Bytes)
			expectedLength := uint64BytesLen + btcec.PubKeyBytesLenCompressed
			if len(lockedDeSoPubKeyConcatKey) != expectedLength {
				return fmt.Errorf("DBGetAllProfilesByLockedDeSo: Invalid key "+
					"length %d should be at least %d", len(lockedDeSoPubKeyConcatKey),
					expectedLength)
			}

			lockedDeSoNanos := DecodeUint64(lockedDeSoPubKeyConcatKey[:uint64BytesLen])

			// Appended to the stake should be the profile pub key so extract it here.
			profilePKID := make([]byte, btcec.PubKeyBytesLenCompressed)
			copy(profilePKID[:], lockedDeSoPubKeyConcatKey[uint64BytesLen:])

			lockedDeSoNanosFetched = append(lockedDeSoNanosFetched, lockedDeSoNanos)
			profilePublicKeysFetched = append(profilePublicKeysFetched, PublicKeyToPKID(profilePKID))
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}

	if !fetchEntries {
		return lockedDeSoNanosFetched, profilePublicKeysFetched, nil, nil
	}

	for _, profilePKID := range profilePublicKeysFetched {
		profileEntry := DBGetProfileEntryForPKID(handle, snap, profilePKID)
		if profileEntry == nil {
			return nil, nil, nil, fmt.Errorf("DBGetAllProfilesByLockedDeSo: "+
				"ProfilePubKey %v does not have corresponding entry",
				PkToStringBoth(profilePKID[:]))
		}
		profileEntriesFetched = append(profileEntriesFetched, profileEntry)
	}

	return lockedDeSoNanosFetched, profilePublicKeysFetched, profileEntriesFetched, nil
}

// =====================================================================================
//
//	Coin balance entry code - Supports both creator coins and DAO coins
//
// =====================================================================================
func _dbGetPrefixForHODLerPKIDCreatorPKIDToBalanceEntry(isDAOCoin bool) []byte {
	if isDAOCoin {
		return Prefixes.PrefixHODLerPKIDCreatorPKIDToDAOCoinBalanceEntry
	} else {
		return Prefixes.PrefixHODLerPKIDCreatorPKIDToBalanceEntry
	}
}

func _dbGetPrefixForCreatorPKIDHODLerPKIDToBalanceEntry(isDAOCoin bool) []byte {
	if isDAOCoin {
		return Prefixes.PrefixCreatorPKIDHODLerPKIDToDAOCoinBalanceEntry
	} else {
		return Prefixes.PrefixCreatorPKIDHODLerPKIDToBalanceEntry
	}
}

func _dbKeyForHODLerPKIDCreatorPKIDToBalanceEntry(hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) []byte {
	key := append([]byte{}, _dbGetPrefixForHODLerPKIDCreatorPKIDToBalanceEntry(isDAOCoin)...)
	key = append(key, hodlerPKID[:]...)
	key = append(key, creatorPKID[:]...)
	return key
}
func _dbKeyForCreatorPKIDHODLerPKIDToBalanceEntry(creatorPKID *PKID, hodlerPKID *PKID, isDAOCoin bool) []byte {
	key := append([]byte{}, _dbGetPrefixForCreatorPKIDHODLerPKIDToBalanceEntry(isDAOCoin)...)
	key = append(key, creatorPKID[:]...)
	key = append(key, hodlerPKID[:]...)
	return key
}

func DBGetBalanceEntryForHODLerAndCreatorPKIDsWithTxn(txn *badger.Txn, snap *Snapshot,
	hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) *BalanceEntry {

	key := _dbKeyForHODLerPKIDCreatorPKIDToBalanceEntry(hodlerPKID, creatorPKID, isDAOCoin)
	balanceEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return &BalanceEntry{
			HODLerPKID:   hodlerPKID.NewPKID(),
			CreatorPKID:  creatorPKID.NewPKID(),
			BalanceNanos: *uint256.NewInt(),
		}
	}
	balanceEntryObj := &BalanceEntry{}
	rr := bytes.NewReader(balanceEntryBytes)
	DecodeFromBytes(balanceEntryObj, rr)
	return balanceEntryObj
}

func DBGetBalanceEntryForHODLerAndCreatorPKIDs(handle *badger.DB, snap *Snapshot,
	hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) *BalanceEntry {

	var ret *BalanceEntry
	handle.View(func(txn *badger.Txn) error {
		ret = DBGetBalanceEntryForHODLerAndCreatorPKIDsWithTxn(
			txn, snap, hodlerPKID, creatorPKID, isDAOCoin)
		return nil
	})
	return ret
}

func DBGetBalanceEntryForCreatorPKIDAndHODLerPubKeyWithTxn(txn *badger.Txn, snap *Snapshot,
	creatorPKID *PKID, hodlerPKID *PKID, isDAOCoin bool) *BalanceEntry {

	key := _dbKeyForCreatorPKIDHODLerPKIDToBalanceEntry(creatorPKID, hodlerPKID, isDAOCoin)
	balanceEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return nil
	}
	balanceEntryObj := &BalanceEntry{}
	rr := bytes.NewReader(balanceEntryBytes)
	DecodeFromBytes(balanceEntryObj, rr)

	return balanceEntryObj
}

func DBDeleteBalanceEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot,
	hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) error {

	// First pull up the mappings that exists for the keys passed in.
	// If one doesn't exist then there's nothing to do.
	balanceEntry := DBGetBalanceEntryForHODLerAndCreatorPKIDsWithTxn(
		txn, snap, hodlerPKID, creatorPKID, isDAOCoin)
	if balanceEntry == nil {
		return nil
	}

	// When an entry exists, delete the mappings for it.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForHODLerPKIDCreatorPKIDToBalanceEntry(hodlerPKID, creatorPKID, isDAOCoin)); err != nil {
		return errors.Wrapf(err, "DBDeleteBalanceEntryMappingsWithTxn: Deleting "+
			"mappings with keys: %v %v",
			PkToStringBoth(hodlerPKID[:]), PkToStringBoth(creatorPKID[:]))
	}
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForCreatorPKIDHODLerPKIDToBalanceEntry(creatorPKID, hodlerPKID, isDAOCoin)); err != nil {
		return errors.Wrapf(err, "DBDeleteBalanceEntryMappingsWithTxn: Deleting "+
			"mappings with keys: %v %v",
			PkToStringBoth(hodlerPKID[:]), PkToStringBoth(creatorPKID[:]))
	}

	// Note: We don't update the CreatorDeSoLockedNanosCreatorPubKeyIIndex
	// because we expect that the caller is keeping the individual holdings in
	// sync with the "total" coins stored in the profile.

	return nil
}

func DBDeleteBalanceEntryMappings(handle *badger.DB, snap *Snapshot,
	hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBDeleteBalanceEntryMappingsWithTxn(
			txn, snap, hodlerPKID, creatorPKID, isDAOCoin)
	})
}

func DBPutBalanceEntryMappingsWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64,
	balanceEntry *BalanceEntry, isDAOCoin bool) error {

	// If the balance is zero, then there is no point in storing this entry.
	// We already placeholder a "zero" balance entry in connect logic.
	if balanceEntry.BalanceNanos.Eq(uint256.NewInt()) && !balanceEntry.HasPurchased {
		return nil
	}

	balanceEntryBytes := EncodeToBytes(blockHeight, balanceEntry)
	// Set the forward direction for the HODLer
	if err := DBSetWithTxn(txn, snap, _dbKeyForHODLerPKIDCreatorPKIDToBalanceEntry(
		balanceEntry.HODLerPKID, balanceEntry.CreatorPKID, isDAOCoin),
		balanceEntryBytes); err != nil {

		return errors.Wrapf(err, "DBPutBalanceEntryMappingsWithTxn: Problem "+
			"adding forward mappings for pub keys: %v %v",
			PkToStringBoth(balanceEntry.HODLerPKID[:]),
			PkToStringBoth(balanceEntry.CreatorPKID[:]))
	}

	// Set the reverse direction for the creator
	if err := DBSetWithTxn(txn, snap, _dbKeyForCreatorPKIDHODLerPKIDToBalanceEntry(
		balanceEntry.CreatorPKID, balanceEntry.HODLerPKID, isDAOCoin),
		balanceEntryBytes); err != nil {

		return errors.Wrapf(err, "DBPutBalanceEntryMappingsWithTxn: Problem "+
			"adding reverse mappings for pub keys: %v %v",
			PkToStringBoth(balanceEntry.HODLerPKID[:]),
			PkToStringBoth(balanceEntry.CreatorPKID[:]))
	}

	return nil
}

func DBPutBalanceEntryMappings(handle *badger.DB, snap *Snapshot, blockHeight uint64,
	balanceEntry *BalanceEntry, isDAOCoin bool) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DBPutBalanceEntryMappingsWithTxn(
			txn, snap, blockHeight, balanceEntry, isDAOCoin)
	})
}

// GetSingleBalanceEntryFromPublicKeys fetches a single balance entry of a holder's creator or DAO coin.
// Returns nil if the balance entry never existed.
// TODO: This is suboptimal, shouldn't be passing UtxoView
func GetSingleBalanceEntryFromPublicKeys(holder []byte, creator []byte, utxoView *UtxoView, isDAOCoin bool) (*BalanceEntry, error) {
	holderPKIDEntry := utxoView.GetPKIDForPublicKey(holder)
	if holderPKIDEntry == nil || holderPKIDEntry.isDeleted {
		return nil, fmt.Errorf("DbGetSingleBalanceEntryFromPublicKeys: holderPKID was nil or deleted; this should never happen")
	}
	holderPKID := holderPKIDEntry.PKID
	creatorPKIDEntry := utxoView.GetPKIDForPublicKey(creator)
	if creatorPKIDEntry == nil || creatorPKIDEntry.isDeleted {
		return nil, fmt.Errorf("DbGetSingleBalanceEntryFromPublicKeys: creatorPKID was nil or deleted; this should never happen")
	}
	creatorPKID := creatorPKIDEntry.PKID

	// Check if there's a balance entry in the view
	balanceEntryMapKey := MakeBalanceEntryKey(holderPKID, creatorPKID)
	balanceEntryFromView := utxoView.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin)[balanceEntryMapKey]
	if balanceEntryFromView != nil {
		return balanceEntryFromView, nil
	}

	// Check if there's a balance entry in the database
	balanceEntryFromDb := DbGetBalanceEntry(utxoView.Handle, utxoView.Snapshot, holderPKID, creatorPKID, isDAOCoin)
	return balanceEntryFromDb, nil
}

// DbGetBalanceEntry returns a balance entry from the database
func DbGetBalanceEntry(db *badger.DB, snap *Snapshot,
	holder *PKID, creator *PKID, isDAOCoin bool) *BalanceEntry {
	var ret *BalanceEntry
	db.View(func(txn *badger.Txn) error {
		ret = DbGetHolderPKIDCreatorPKIDToBalanceEntryWithTxn(txn, snap, holder, creator, isDAOCoin)
		return nil
	})
	return ret
}

func DbGetHolderPKIDCreatorPKIDToBalanceEntryWithTxn(txn *badger.Txn, snap *Snapshot,
	holder *PKID, creator *PKID, isDAOCoin bool) *BalanceEntry {

	key := _dbKeyForCreatorPKIDHODLerPKIDToBalanceEntry(creator, holder, isDAOCoin)
	balanceEntryBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		return &BalanceEntry{
			HODLerPKID:   holder.NewPKID(),
			CreatorPKID:  creator.NewPKID(),
			BalanceNanos: *uint256.NewInt(),
		}
	}

	balanceEntryObj := &BalanceEntry{}
	rr := bytes.NewReader(balanceEntryBytes)
	DecodeFromBytes(balanceEntryObj, rr)
	return balanceEntryObj
}

// DbGetBalanceEntriesYouHold fetches the BalanceEntries that the passed in pkid holds.
func DbGetBalanceEntriesYouHold(db *badger.DB, snap *Snapshot, pkid *PKID, filterOutZeroBalances bool, isDAOCoin bool) ([]*BalanceEntry, error) {
	// Get the balance entries for the coins that *you hold*
	balanceEntriesYouHodl := []*BalanceEntry{}
	{
		prefix := _dbGetPrefixForHODLerPKIDCreatorPKIDToBalanceEntry(isDAOCoin)
		keyPrefix := append(prefix, pkid[:]...)
		_, entryByteStringsFound := _enumerateKeysForPrefix(db, keyPrefix)
		for _, byteString := range entryByteStringsFound {
			currentEntry := &BalanceEntry{}
			rr := bytes.NewReader(byteString)
			DecodeFromBytes(currentEntry, rr)
			if filterOutZeroBalances && currentEntry.BalanceNanos.IsZero() {
				continue
			}
			balanceEntriesYouHodl = append(balanceEntriesYouHodl, currentEntry)
		}
	}

	return balanceEntriesYouHodl, nil
}

// DbGetBalanceEntriesHodlingYou fetches the BalanceEntries that hold the pkid passed in.
func DbGetBalanceEntriesHodlingYou(db *badger.DB, snap *Snapshot, pkid *PKID, filterOutZeroBalances bool, isDAOCoin bool) ([]*BalanceEntry, error) {
	// Get the balance entries for the coins that *hold you*
	balanceEntriesThatHodlYou := []*BalanceEntry{}
	{
		prefix := _dbGetPrefixForCreatorPKIDHODLerPKIDToBalanceEntry(isDAOCoin)
		keyPrefix := append(prefix, pkid[:]...)
		_, entryByteStringsFound := _enumerateKeysForPrefix(db, keyPrefix)
		for _, byteString := range entryByteStringsFound {
			currentEntry := &BalanceEntry{}
			rr := bytes.NewReader(byteString)
			DecodeFromBytes(currentEntry, rr)
			if filterOutZeroBalances && currentEntry.BalanceNanos.IsZero() {
				continue
			}
			balanceEntriesThatHodlYou = append(balanceEntriesThatHodlYou, currentEntry)
		}
	}

	return balanceEntriesThatHodlYou, nil
}

// =====================================================================================
// End coin balance entry code
// =====================================================================================

// startPrefix specifies a point in the DB at which the iteration should start.
// It doesn't have to map to an exact key because badger will just binary search
// and start right before/after that location.
//
// validForPrefix helps determine when the iteration should stop. The iteration
// stops at the last entry that has this prefix. Setting it to
// an empty byte string would cause the iteration to seek to the beginning of the db,
// whereas setting it to one of the Prefix bytes would cause the iteration to stop
// at the last entry with that prefix.
//
// maxKeyLen is required so we can pad the key with FF in the case the user wants
// to seek backwards. This is required due to a quirk of badgerdb. It is ignored
// if reverse == false.
//
// numToFetch specifies the number of entries to fetch. If set to zero then it
// fetches all entries that match the validForPrefix passed in.
func DBGetPaginatedKeysAndValuesForPrefixWithTxn(
	txn *badger.Txn, startPrefix []byte, validForPrefix []byte,
	maxKeyLen int, numToFetch int, reverse bool, fetchValues bool) (

	_keysFound [][]byte, _valsFound [][]byte, _err error) {

	keysFound := [][]byte{}
	valsFound := [][]byte{}

	opts := badger.DefaultIteratorOptions

	opts.PrefetchValues = fetchValues

	// Optionally go in reverse order.
	opts.Reverse = reverse

	it := txn.NewIterator(opts)
	defer it.Close()
	prefix := startPrefix
	if reverse {
		// When we iterate backwards, the prefix must be bigger than all possible
		// keys that could actually exist with this prefix. We achieve this by
		// padding the end of the dbPrefixx passed in up to the key length.
		prefix = make([]byte, maxKeyLen)
		for ii := 0; ii < maxKeyLen; ii++ {
			if ii < len(startPrefix) {
				prefix[ii] = startPrefix[ii]
			} else {
				prefix[ii] = 0xFF
			}
		}
	}
	for it.Seek(prefix); it.ValidForPrefix(validForPrefix); it.Next() {
		keyCopy := it.Item().KeyCopy(nil)
		if maxKeyLen != 0 && len(keyCopy) != maxKeyLen {
			return nil, nil, fmt.Errorf(
				"DBGetPaginatedKeysAndValuesForPrefixWithTxn: Invalid key length %v != %v",
				len(keyCopy), maxKeyLen)
		}

		var valCopy []byte
		if fetchValues {
			var err error
			valCopy, err = it.Item().ValueCopy(nil)
			if err != nil {
				return nil, nil, fmt.Errorf("DBGetPaginatedKeysAndValuesForPrefixWithTxn: "+
					"Error fetching value: %v", err)
			}
		}

		keysFound = append(keysFound, keyCopy)
		valsFound = append(valsFound, valCopy)

		if numToFetch != 0 && len(keysFound) == numToFetch {
			break
		}
	}

	// Return whatever we found.
	return keysFound, valsFound, nil
}

func DBGetPaginatedKeysAndValuesForPrefix(
	db *badger.DB, startPrefix []byte, validForPrefix []byte,
	keyLen int, numToFetch int, reverse bool, fetchValues bool) (
	_keysFound [][]byte, _valsFound [][]byte, _err error) {

	keysFound := [][]byte{}
	valsFound := [][]byte{}

	dbErr := db.View(func(txn *badger.Txn) error {
		var err error
		keysFound, valsFound, err = DBGetPaginatedKeysAndValuesForPrefixWithTxn(
			txn, startPrefix, validForPrefix, keyLen,
			numToFetch, reverse, fetchValues)
		if err != nil {
			return fmt.Errorf("DBGetPaginatedKeysAndValuesForPrefix: %v", err)
		}
		return nil
	})
	if dbErr != nil {
		return nil, nil, dbErr
	}

	return keysFound, valsFound, nil
}

func DBGetPaginatedPostsOrderedByTime(
	db *badger.DB, snap *Snapshot, startPostTimestampNanos uint64,
	startPostHash *BlockHash, numToFetch int, fetchPostEntries bool, reverse bool) (
	_postHashes []*BlockHash, _tstampNanos []uint64, _postEntries []*PostEntry,
	_err error) {

	startPostPrefix := append([]byte{}, Prefixes.PrefixTstampNanosPostHash...)

	if startPostTimestampNanos > 0 {
		startTstampBytes := EncodeUint64(startPostTimestampNanos)
		startPostPrefix = append(startPostPrefix, startTstampBytes...)
	}

	if startPostHash != nil {
		startPostPrefix = append(startPostPrefix, startPostHash[:]...)
	}

	// We fetch in reverse to get the latest posts.
	maxUint64Tstamp := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	postIndexKeys, _, err := DBGetPaginatedKeysAndValuesForPrefix(
		db, startPostPrefix, Prefixes.PrefixTstampNanosPostHash, /*validForPrefix*/
		len(Prefixes.PrefixTstampNanosPostHash)+len(maxUint64Tstamp)+HashSizeBytes, /*keyLen*/
		numToFetch, reverse /*reverse*/, false /*fetchValues*/)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("DBGetPaginatedPostsOrderedByTime: %v", err)
	}

	// Cut the post hashes and timestamps out of the returned keys.
	postHashes := []*BlockHash{}
	tstamps := []uint64{}
	startTstampIndex := len(Prefixes.PrefixTstampNanosPostHash)
	hashStartIndex := len(Prefixes.PrefixTstampNanosPostHash) + len(maxUint64Tstamp)
	hashEndIndex := hashStartIndex + HashSizeBytes
	for _, postKeyBytes := range postIndexKeys {
		currentPostHash := &BlockHash{}
		copy(currentPostHash[:], postKeyBytes[hashStartIndex:hashEndIndex])
		postHashes = append(postHashes, currentPostHash)

		tstamps = append(tstamps, DecodeUint64(
			postKeyBytes[startTstampIndex:hashStartIndex]))
	}

	// Fetch the PostEntries if desired.
	var postEntries []*PostEntry
	if fetchPostEntries {
		for _, postHash := range postHashes {
			postEntry := DBGetPostEntryByPostHash(db, snap, postHash)
			if postEntry == nil {
				return nil, nil, nil, fmt.Errorf("DBGetPaginatedPostsOrderedByTime: "+
					"PostHash %v does not have corresponding entry", postHash)
			}
			postEntries = append(postEntries, postEntry)
		}
	}

	return postHashes, tstamps, postEntries, nil
}

func DBGetProfilesByUsernamePrefixAndDeSoLocked(db *badger.DB,
	snap *Snapshot, usernamePrefix string, utxoView *UtxoView) (
	_profileEntries []*ProfileEntry, _err error) {

	startPrefix := append([]byte{}, Prefixes.PrefixProfileUsernameToPKID...)
	lowercaseUsernamePrefixString := strings.ToLower(usernamePrefix)
	lowercaseUsernamePrefix := []byte(lowercaseUsernamePrefixString)
	startPrefix = append(startPrefix, lowercaseUsernamePrefix...)

	_, pkidsFound, err := DBGetPaginatedKeysAndValuesForPrefix(
		db /*db*/, startPrefix, /*startPrefix*/
		startPrefix /*validForPrefix*/, 0, /*keyLen (ignored when reverse == false)*/
		0 /*numToFetch (zero fetches all)*/, false, /*reverse*/
		true /*fetchValues*/)
	if err != nil {
		return nil, fmt.Errorf("DBGetProfilesByUsernamePrefixAndDeSoLocked: %v", err)
	}

	// Have to do this to convert the PKIDs back into public keys
	// TODO: We should clean things up around public keys vs PKIDs
	pubKeysMap := make(map[PkMapKey][]byte)
	for _, pkidBytesIter := range pkidsFound {
		pkidBytes := pkidBytesIter
		if len(pkidBytes) != btcec.PubKeyBytesLenCompressed {
			continue
		}
		pkid := &PKID{}
		copy(pkid[:], pkidBytes)
		pubKey := DBGetPublicKeyForPKID(db, snap, pkid)
		if len(pubKey) != 0 {
			pubKeysMap[MakePkMapKey(pubKey)] = pubKey
		}
	}

	for username, profileEntry := range utxoView.ProfileUsernameToProfileEntry {
		if strings.HasPrefix(string(username[:]), lowercaseUsernamePrefixString) {
			pkMapKey := MakePkMapKey(profileEntry.PublicKey)
			pubKeysMap[pkMapKey] = profileEntry.PublicKey
		}
	}

	// Sigh.. convert the public keys *back* into PKIDs...
	profilesFound := []*ProfileEntry{}
	for _, pkIter := range pubKeysMap {
		pk := pkIter
		pkid := utxoView.GetPKIDForPublicKey(pk).PKID
		profile := utxoView.GetProfileEntryForPKID(pkid)
		// Double-check that a username matches the prefix.
		// If a user had the handle "elon" and then changed to "jeff" and that transaction hadn't mined yet,
		// we would return the profile for "jeff" when we search for "elon" which is incorrect.
		if profile != nil && strings.HasPrefix(strings.ToLower(string(profile.Username[:])), lowercaseUsernamePrefixString) {
			profilesFound = append(profilesFound, profile)
		}
	}

	// If there is no error, sort and return numToFetch. Username searches are always
	// sorted by coin value.
	sort.Slice(profilesFound, func(ii, jj int) bool {
		return profilesFound[ii].CreatorCoinEntry.DeSoLockedNanos > profilesFound[jj].CreatorCoinEntry.DeSoLockedNanos
	})

	return profilesFound, nil
}

// DBGetPaginatedProfilesByDeSoLocked returns up to 'numToFetch' profiles from the db.
func DBGetPaginatedProfilesByDeSoLocked(
	db *badger.DB, snap *Snapshot, startDeSoLockedNanos uint64,
	startProfilePubKeyy []byte, numToFetch int, fetchProfileEntries bool) (
	_profilePublicKeys [][]byte, _profileEntries []*ProfileEntry, _err error) {

	// Convert the start public key to a PKID.
	pkidEntry := DBGetPKIDEntryForPublicKey(db, snap, startProfilePubKeyy)

	startProfilePrefix := append([]byte{}, Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID...)
	var startDeSoLockedBytes []byte
	if pkidEntry != nil {
		startDeSoLockedBytes = EncodeUint64(startDeSoLockedNanos)
		startProfilePrefix = append(startProfilePrefix, startDeSoLockedBytes...)
		startProfilePrefix = append(startProfilePrefix, pkidEntry.PKID[:]...)
	} else {
		// If no pub key is provided, we just max out deso locked and start at the top of the list.
		maxBigEndianUint64Bytes := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
		startDeSoLockedBytes = maxBigEndianUint64Bytes
		startProfilePrefix = append(startProfilePrefix, startDeSoLockedBytes...)
	}

	keyLen := len(Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID) + len(startDeSoLockedBytes) + btcec.PubKeyBytesLenCompressed
	// We fetch in reverse to get the profiles with the most DeSo locked.
	profileIndexKeys, _, err := DBGetPaginatedKeysAndValuesForPrefix(
		db, startProfilePrefix, Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID, /*validForPrefix*/
		keyLen /*keyLen*/, numToFetch,
		true /*reverse*/, false /*fetchValues*/)
	if err != nil {
		return nil, nil, fmt.Errorf("DBGetPaginatedProfilesByDeSoLocked: %v", err)
	}

	// Cut the pkids out of the returned keys.
	profilePKIDs := [][]byte{}
	startPKIDIndex := len(Prefixes.PrefixCreatorDeSoLockedNanosCreatorPKID) + len(startDeSoLockedBytes)
	endPKIDIndex := startPKIDIndex + btcec.PubKeyBytesLenCompressed
	for _, profileKeyBytes := range profileIndexKeys {
		currentPKID := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(currentPKID[:], profileKeyBytes[startPKIDIndex:endPKIDIndex][:])
		profilePKIDs = append(profilePKIDs, currentPKID)
	}

	profilePubKeys := [][]byte{}
	for _, pkidBytesIter := range profilePKIDs {
		pkidBytes := pkidBytesIter
		pkid := &PKID{}
		copy(pkid[:], pkidBytes)
		profilePubKeys = append(profilePubKeys, DBGetPublicKeyForPKID(db, snap, pkid))
	}

	if !fetchProfileEntries {
		return profilePubKeys, nil, nil
	}

	// Fetch the ProfileEntries if desired.
	var profileEntries []*ProfileEntry
	for _, profilePKID := range profilePKIDs {
		pkid := &PKID{}
		copy(pkid[:], profilePKID)
		profileEntry := DBGetProfileEntryForPKID(db, snap, pkid)
		if profileEntry == nil {
			return nil, nil, fmt.Errorf("DBGetAllProfilesByLockedDeSo: "+
				"ProfilePKID %v does not have corresponding entry",
				PkToStringBoth(profilePKID))
		}
		profileEntries = append(profileEntries, profileEntry)
	}

	return profilePubKeys, profileEntries, nil
}

// ---------------------------------------------
// DAO coin limit order
// ---------------------------------------------

func DBKeyForDAOCoinLimitOrder(order *DAOCoinLimitOrderEntry) []byte {
	key := DBPrefixKeyForDAOCoinLimitOrder(order)
	key = append(key, EncodeUint256(order.ScaledExchangeRateCoinsToSellPerCoinToBuy)...)
	// Store MaxUint32 - block height to guarantee FIFO
	// orders as we seek in reverse order.
	key = append(key, _EncodeUint32(math.MaxUint32-order.BlockHeight)...)
	key = append(key, order.OrderID.ToBytes()...)
	return key
}

func DBPrefixKeyForDAOCoinLimitOrder(order *DAOCoinLimitOrderEntry) []byte {
	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrder...)
	key = append(key, order.BuyingDAOCoinCreatorPKID.ToBytes()...)
	key = append(key, order.SellingDAOCoinCreatorPKID.ToBytes()...)
	return key
}

func DBKeyForDAOCoinLimitOrderByTransactorPKID(order *DAOCoinLimitOrderEntry) []byte {
	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrderByTransactorPKID...)
	key = append(key, order.TransactorPKID.ToBytes()...)
	key = append(key, order.BuyingDAOCoinCreatorPKID.ToBytes()...)
	key = append(key, order.SellingDAOCoinCreatorPKID.ToBytes()...)
	key = append(key, order.OrderID.ToBytes()...)
	return key
}

func DBKeyForDAOCoinLimitOrderByOrderID(order *DAOCoinLimitOrderEntry) []byte {
	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrderByOrderID...)
	key = append(key, order.OrderID.ToBytes()...)
	return key
}

func DBGetDAOCoinLimitOrder(handle *badger.DB, snap *Snapshot, orderID *BlockHash) (
	*DAOCoinLimitOrderEntry, error) {

	var ret *DAOCoinLimitOrderEntry
	var err error

	handle.View(func(txn *badger.Txn) error {
		ret, err = DBGetDAOCoinLimitOrderWithTxn(txn, snap, orderID)
		return nil
	})

	return ret, err
}

func DBGetDAOCoinLimitOrderWithTxn(txn *badger.Txn, snap *Snapshot, orderID *BlockHash) (
	_order *DAOCoinLimitOrderEntry, _err error) {

	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrderByOrderID...)
	key = append(key, orderID.ToBytes()...)
	orderBytes, err := DBGetWithTxn(txn, snap, key)
	if err != nil {
		// We don't want to error if the key isn't found.
		// Instead, we just want to return nil.
		if err == badger.ErrKeyNotFound {
			return nil, nil
		}

		return nil, errors.Wrapf(err, "DBGetDAOCoinLimitOrder: problem getting limit order")
	}

	order := &DAOCoinLimitOrderEntry{}
	rr := bytes.NewReader(orderBytes)
	if exist, err := DecodeFromBytes(order, rr); !exist || err != nil {
		return nil, errors.Wrapf(err, "DBGetDAOCoinLimitOrder: problem decoding limit order")
	}

	return order, nil
}

func DBGetMatchingDAOCoinLimitOrders(
	txn *badger.Txn, inputOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry,
	orderEntriesInView map[DAOCoinLimitOrderMapKey]bool) ([]*DAOCoinLimitOrderEntry, error) {

	queryOrder := inputOrder.Copy()
	queryQuantityToFill := queryOrder.QuantityToFillInBaseUnits.Clone()

	// Convert the input BID order to the ASK order to query for.
	// Note that we seek in reverse for the best matching orders.
	//   * Swap BuyingDAOCoinCreatorPKID and SellingDAOCoinCreatorPKID.
	//   * Set ScaledExchangeRateCoinsToSellPerCoinToBuy to MaxUint256.
	//   * Set BlockHeight to 0 as this becomes math.MaxUint32 in the key.
	//   * Set OrderID to MaxBlockHash.
	queryOrder.BuyingDAOCoinCreatorPKID = inputOrder.SellingDAOCoinCreatorPKID
	queryOrder.SellingDAOCoinCreatorPKID = inputOrder.BuyingDAOCoinCreatorPKID
	queryOrder.ScaledExchangeRateCoinsToSellPerCoinToBuy = MaxUint256.Clone()
	queryOrder.BlockHeight = uint32(0)
	queryOrder.OrderID = maxHash.NewBlockHash()

	key := DBKeyForDAOCoinLimitOrder(queryOrder)
	prefixKey := DBPrefixKeyForDAOCoinLimitOrder(queryOrder)

	// If passed a last seen order, start seeking from there.
	var startKey []byte
	if lastSeenOrder != nil {
		startKey = DBKeyForDAOCoinLimitOrder(lastSeenOrder)
		key = startKey
	}

	// Go in reverse order to find the highest prices first.
	// We break once we hit the input order's inverted scaled
	// price or the input order's quantity is fulfilled.
	opts := badger.DefaultIteratorOptions
	opts.Reverse = true
	iterator := txn.NewIterator(opts)
	defer iterator.Close()

	// Seek first matching order.
	matchingOrders := []*DAOCoinLimitOrderEntry{}

	for iterator.Seek(key); iterator.ValidForPrefix(prefixKey) && queryQuantityToFill.GtUint64(0); iterator.Next() {
		// If picking up from where you left off, skip the first order which
		// has already been processed previously.
		if len(startKey) != 0 && bytes.Equal(key, startKey) {
			startKey = nil
			continue
		}

		matchingOrderBytes, err := iterator.Item().ValueCopy(nil)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetMatchingDAOCoinLimitOrders: problem getting limit order")
		}

		matchingOrder := &DAOCoinLimitOrderEntry{}
		rr := bytes.NewReader(matchingOrderBytes)
		if exist, err := DecodeFromBytes(matchingOrder, rr); !exist || err != nil {
			return nil, errors.Wrapf(err, "DBGetMatchingDAOCoinLimitOrders: problem decoding limit order")
		}

		// Skip if order is already in the view.
		if _, exists := orderEntriesInView[matchingOrder.ToMapKey()]; exists {
			continue
		}

		// Validate matching order's price.
		if !inputOrder.IsValidMatchingOrderPrice(matchingOrder) {
			break
		}

		// Calculate how the transactor's quantity to fill will change
		// after being matched with this order. If the transactor still
		// has quantity to fill, we loop.
		queryQuantityToFill, _, _, _, err = _calculateDAOCoinsTransferredInLimitOrderMatch(
			matchingOrder, queryOrder.OperationType, queryQuantityToFill)
		if err != nil {
			return nil, errors.Wrapf(err, "DBGetMatchingDAOCoinLimitOrders: ")
		}

		matchingOrders = append(matchingOrders, matchingOrder)
	}

	return matchingOrders, nil
}

func DBGetAllDAOCoinLimitOrders(handle *badger.DB) ([]*DAOCoinLimitOrderEntry, error) {
	// Get all DAO Coin limit orders.
	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrder...)
	return _DBGetAllDAOCoinLimitOrdersByPrefix(handle, key)
}

func DBGetAllDAOCoinLimitOrdersForThisDAOCoinPair(
	handle *badger.DB,
	buyingDAOCoinCreatorPKID *PKID,
	sellingDAOCoinCreatorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {

	// Get all DAO coin limit orders for this DAO coin pair.
	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrder...)
	key = append(key, buyingDAOCoinCreatorPKID.ToBytes()...)
	key = append(key, sellingDAOCoinCreatorPKID.ToBytes()...)
	return _DBGetAllDAOCoinLimitOrdersByPrefix(handle, key)
}

func DBGetAllDAOCoinLimitOrdersForThisTransactor(handle *badger.DB, transactorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	// Get all DAO coin limit orders for this transactor.
	key := append([]byte{}, Prefixes.PrefixDAOCoinLimitOrderByTransactorPKID...)
	key = append(key, transactorPKID[:]...)
	return _DBGetAllDAOCoinLimitOrdersByPrefix(handle, key)
}

func _DBGetAllDAOCoinLimitOrdersByPrefix(handle *badger.DB, prefixKey []byte) ([]*DAOCoinLimitOrderEntry, error) {
	// Get all DAO coin limit orders containing this prefix.
	_, valsFound := _enumerateKeysForPrefix(handle, prefixKey)
	orders := []*DAOCoinLimitOrderEntry{}

	// Cast resulting values from bytes to order entries.
	for _, valBytes := range valsFound {
		order := &DAOCoinLimitOrderEntry{}
		rr := bytes.NewReader(valBytes)
		if exist, err := DecodeFromBytes(order, rr); !exist || err != nil {
			return nil, errors.Wrapf(err, "DBGetAllDAOCoinLimitOrdersByPrefixKey: problem getting limit orders")
		}

		orders = append(orders, order)
	}

	return orders, nil
}

func DBPutDAOCoinLimitOrderWithTxn(txn *badger.Txn, snap *Snapshot, order *DAOCoinLimitOrderEntry, blockHeight uint64) error {
	if order == nil {
		return nil
	}

	orderBytes := EncodeToBytes(blockHeight, order)
	// Store in index: PrefixDAOCoinLimitOrderByTransactorPKID
	key := DBKeyForDAOCoinLimitOrder(order)

	if err := DBSetWithTxn(txn, snap, key, orderBytes); err != nil {
		return errors.Wrapf(err, "DBPutDAOCoinLimitOrderWithTxn: problem storing limit order")
	}

	// Store in index: PrefixDAOCoinLimitOrderByTransactorPKID
	key = DBKeyForDAOCoinLimitOrderByTransactorPKID(order)
	if err := DBSetWithTxn(txn, snap, key, orderBytes); err != nil {
		return errors.Wrapf(err, "DBPutDAOCoinLimitOrderWithTxn: problem storing limit order")
	}

	// Store in index: PrefixDAOCoinLimitOrderByOrderID
	key = DBKeyForDAOCoinLimitOrderByOrderID(order)
	if err := DBSetWithTxn(txn, snap, key, orderBytes); err != nil {
		return errors.Wrapf(err, "DBPutDAOCoinLimitOrderWithTxn: problem storing order in index PrefixDAOCoinLimitOrderByOrderID")
	}

	return nil
}

func DBDeleteDAOCoinLimitOrderWithTxn(txn *badger.Txn, snap *Snapshot, order *DAOCoinLimitOrderEntry) error {
	if order == nil {
		return nil
	}

	// Delete from index: PrefixDAOCoinLimitOrder
	key := DBKeyForDAOCoinLimitOrder(order)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(err, "DBDeleteDAOCoinLimitOrderWithTxn: problem deleting limit order")
	}

	// Delete from index: PrefixDAOCoinLimitOrderByTransactorPKID
	key = DBKeyForDAOCoinLimitOrderByTransactorPKID(order)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(err, "DBDeleteDAOCoinLimitOrderWithTxn: problem deleting limit order")
	}

	// Store in index: PrefixDAOCoinLimitOrderByOrderID
	key = DBKeyForDAOCoinLimitOrderByOrderID(order)
	if err := DBDeleteWithTxn(txn, snap, key); err != nil {
		return errors.Wrapf(err, "DBDeleteDAOCoinLimitOrderWithTxn: problem deleting order from index PrefixDAOCoinLimitOrderByOrderID")
	}

	return nil
}

// -------------------------------------------------------------------------------------
// Mempool Txn mapping funcions
// <prefix_id, txn hash BlockHash> -> <*MsgDeSoTxn>
// -------------------------------------------------------------------------------------

func _dbKeyForMempoolTxn(mempoolTx *MempoolTx) []byte {
	// Make a copy to avoid multiple calls to this function re-using the same slice.
	prefixCopy := append([]byte{}, Prefixes.PrefixMempoolTxnHashToMsgDeSoTxn...)
	timeAddedBytes := EncodeUint64(uint64(mempoolTx.Added.UnixNano()))
	key := append(prefixCopy, timeAddedBytes...)
	key = append(key, mempoolTx.Hash[:]...)

	return key
}

func DbPutMempoolTxnWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64, mempoolTx *MempoolTx) error {

	mempoolTxnBytes, err := mempoolTx.Tx.ToBytes(false /*preSignatureBool*/)
	if err != nil {
		return errors.Wrapf(err, "DbPutMempoolTxnWithTxn: Problem encoding mempoolTxn to bytes.")
	}

	if err := DBSetWithTxn(txn, snap, _dbKeyForMempoolTxn(mempoolTx), mempoolTxnBytes); err != nil {
		return errors.Wrapf(err, "DbPutMempoolTxnWithTxn: Problem putting mapping for txn hash: %s", mempoolTx.Hash.String())
	}

	return nil
}

func DbPutMempoolTxn(handle *badger.DB, snap *Snapshot, blockHeight uint64, mempoolTx *MempoolTx) error {

	return handle.Update(func(txn *badger.Txn) error {
		return DbPutMempoolTxnWithTxn(txn, snap, blockHeight, mempoolTx)
	})
}

func DbGetMempoolTxnWithTxn(txn *badger.Txn, snap *Snapshot, mempoolTx *MempoolTx) *MsgDeSoTxn {

	mempoolTxnObj := &MsgDeSoTxn{}
	mempoolTxnBytes, err := DBGetWithTxn(txn, snap, _dbKeyForMempoolTxn(mempoolTx))
	if err != nil {
		return nil
	}

	err = mempoolTxnObj.FromBytes(mempoolTxnBytes)
	if err != nil {
		return nil
	}
	return mempoolTxnObj
}

func DbGetMempoolTxn(db *badger.DB, snap *Snapshot, mempoolTx *MempoolTx) *MsgDeSoTxn {
	var ret *MsgDeSoTxn
	db.View(func(txn *badger.Txn) error {
		ret = DbGetMempoolTxnWithTxn(txn, snap, mempoolTx)
		return nil
	})
	return ret
}

func DbGetAllMempoolTxnsSortedByTimeAdded(handle *badger.DB) (_mempoolTxns []*MsgDeSoTxn, _error error) {
	_, valuesFound := _enumerateKeysForPrefix(handle, Prefixes.PrefixMempoolTxnHashToMsgDeSoTxn)

	mempoolTxns := []*MsgDeSoTxn{}
	for _, mempoolTxnBytes := range valuesFound {
		mempoolTxn := &MsgDeSoTxn{}
		err := mempoolTxn.FromBytes(mempoolTxnBytes)
		if err != nil {
			return nil, errors.Wrapf(err, "DbGetAllMempoolTxnsSortedByTimeAdded: failed to decode mempoolTxnBytes.")
		}
		mempoolTxns = append(mempoolTxns, mempoolTxn)
	}

	// We don't need to sort the transactions because the DB keys include the time added and
	// are therefore retrieved from badger in order.

	return mempoolTxns, nil
}

func DbDeleteAllMempoolTxnsWithTxn(txn *badger.Txn, snap *Snapshot) error {
	txnKeysFound, _, err := _enumerateKeysForPrefixWithTxn(txn, Prefixes.PrefixMempoolTxnHashToMsgDeSoTxn)
	if err != nil {
		return errors.Wrapf(err, "DbDeleteAllMempoolTxnsWithTxn: ")
	}

	for _, txnKey := range txnKeysFound {
		err := DbDeleteMempoolTxnKeyWithTxn(txn, snap, txnKey)
		if err != nil {
			return errors.Wrapf(err, "DbDeleteAllMempoolTxMappings: Deleting mempool txnKey failed.")
		}
	}

	return nil
}

func FlushMempoolToDbWithTxn(txn *badger.Txn, snap *Snapshot, blockHeight uint64, allTxns []*MempoolTx) error {
	for _, mempoolTx := range allTxns {
		err := DbPutMempoolTxnWithTxn(txn, snap, blockHeight, mempoolTx)
		if err != nil {
			return errors.Wrapf(err, "FlushMempoolToDb: Putting "+
				"mempool tx hash %s failed.", mempoolTx.Hash.String())
		}
	}

	return nil
}

func FlushMempoolToDb(handle *badger.DB, snap *Snapshot, blockHeight uint64, allTxns []*MempoolTx) error {
	err := handle.Update(func(txn *badger.Txn) error {
		return FlushMempoolToDbWithTxn(txn, snap, blockHeight, allTxns)
	})
	if err != nil {
		return err
	}

	return nil
}

func DbDeleteAllMempoolTxns(handle *badger.DB, snap *Snapshot) error {
	handle.Update(func(txn *badger.Txn) error {
		return DbDeleteAllMempoolTxnsWithTxn(txn, snap)
	})

	return nil
}

func DbDeleteMempoolTxnWithTxn(txn *badger.Txn, snap *Snapshot, mempoolTx *MempoolTx) error {

	// When a mapping exists, delete it.
	if err := DBDeleteWithTxn(txn, snap, _dbKeyForMempoolTxn(mempoolTx)); err != nil {
		return errors.Wrapf(err, "DbDeleteMempoolTxMappingWithTxn: Deleting "+
			"mempool tx key failed.")
	}

	return nil
}

func DbDeleteMempoolTxn(handle *badger.DB, snap *Snapshot, mempoolTx *MempoolTx) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteMempoolTxnWithTxn(txn, snap, mempoolTx)
	})
}

func DbDeleteMempoolTxnKey(handle *badger.DB, snap *Snapshot, txnKey []byte) error {
	return handle.Update(func(txn *badger.Txn) error {
		return DbDeleteMempoolTxnKeyWithTxn(txn, snap, txnKey)
	})
}

func DbDeleteMempoolTxnKeyWithTxn(txn *badger.Txn, snap *Snapshot, txnKey []byte) error {

	// When a mapping exists, delete it.
	if err := DBDeleteWithTxn(txn, snap, txnKey); err != nil {
		return errors.Wrapf(err, "DbDeleteMempoolTxMappingWithTxn: Deleting "+
			"mempool tx key failed.")
	}

	return nil
}

func LogDBSummarySnapshot(db *badger.DB) {
	keyCountMap := make(map[byte]int)
	for prefixByte := byte(0); prefixByte < byte(40); prefixByte++ {
		keysForPrefix, _ := EnumerateKeysForPrefix(db, []byte{prefixByte})
		keyCountMap[prefixByte] = len(keysForPrefix)
	}
	glog.Info(spew.Printf("LogDBSummarySnapshot: Current DB summary snapshot: %v", keyCountMap))
}

func StartDBSummarySnapshots(db *badger.DB) {
	// Periodically count the number of keys for each prefix in the DB and log.
	go func() {
		for {
			// Figure out how many keys there are for each prefix and log.
			glog.Info("StartDBSummarySnapshots: Counting DB keys...")
			LogDBSummarySnapshot(db)
			time.Sleep(30 * time.Second)
		}
	}()
}

const (
	// PerformanceMemTableSize is 3072 MB. Increases the maximum
	// amount of data we can commit in a single transaction.
	PerformanceMemTableSize = 3072 << 20

	// PerformanceLogValueSize is 256 MB.
	PerformanceLogValueSize = 256 << 20
)

// PerformanceBadgerOptions are performance geared
// BadgerDB options that use much more RAM than the
// default settings.
func PerformanceBadgerOptions(dir string) badger.Options {
	opts := badger.DefaultOptions(dir)

	// Use an extended table size for larger commits.
	opts.MemTableSize = PerformanceMemTableSize
	opts.ValueLogFileSize = PerformanceLogValueSize

	return opts
}
