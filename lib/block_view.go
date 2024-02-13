package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"

	"github.com/btcsuite/btcd/wire"
	"github.com/holiman/uint256"

	"github.com/davecgh/go-spew/spew"

	"github.com/btcsuite/btcd/btcec"
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

	// Messaging group entries.
	MessagingGroupKeyToMessagingGroupEntry map[MessagingGroupKey]*MessagingGroupEntry

	// Access group entries.
	AccessGroupIdToAccessGroupEntry map[AccessGroupId]*AccessGroupEntry

	// Group Memberships
	AccessGroupMembershipKeyToAccessGroupMember map[AccessGroupMembershipKey]*AccessGroupMemberEntry

	// Postgres stores message data slightly differently
	MessageMap map[BlockHash]*PGMessage

	// Group Chat and Dm messages.
	GroupChatMessagesIndex map[GroupChatMessageKey]*NewMessageEntry
	DmMessagesIndex        map[DmMessageKey]*NewMessageEntry

	// Dm threads.
	DmThreadIndex map[DmThreadKey]*DmThreadEntry

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

	// Creator coin balance entries
	HODLerPKIDCreatorPKIDToBalanceEntry map[BalanceEntryMapKey]*BalanceEntry

	// DAO coin balance entries
	HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry map[BalanceEntryMapKey]*BalanceEntry

	// Derived Key entries. Map key is a combination of owner and derived public keys.
	DerivedKeyToDerivedEntry map[DerivedKeyMapKey]*DerivedKeyEntry

	// DAO coin limit order entry mapping.
	DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry map[DAOCoinLimitOrderMapKey]*DAOCoinLimitOrderEntry

	// Association mappings
	AssociationMapKeyToUserAssociationEntry map[AssociationMapKey]*UserAssociationEntry
	AssociationMapKeyToPostAssociationEntry map[AssociationMapKey]*PostAssociationEntry

	// Map of DeSoNonce and PKID to TransactorNonceEntry
	TransactorNonceMapKeyToTransactorNonceEntry map[TransactorNonceMapKey]*TransactorNonceEntry

	// Validator mappings
	ValidatorPKIDToValidatorEntry map[PKID]*ValidatorEntry
	// ValidatorBLSPublicKeyPKIDPairEntries is a mapping of BLS Public Key to BLSPublicKeyPKIDPairEntry.
	// Used for enforcing uniqueness of BLS Public Keys in the validator set.
	ValidatorBLSPublicKeyPKIDPairEntries map[bls.SerializedPublicKey]*BLSPublicKeyPKIDPairEntry

	// Stake mappings
	StakeMapKeyToStakeEntry map[StakeMapKey]*StakeEntry

	// Locked stake mappings
	LockedStakeMapKeyToLockedStakeEntry map[LockedStakeMapKey]*LockedStakeEntry

	// Locked DAO coin and locked DESO balance entry mapping.
	// NOTE: See comment on LockedBalanceEntryKey before altering.
	LockedBalanceEntryKeyToLockedBalanceEntry map[LockedBalanceEntryKey]*LockedBalanceEntry

	// Lockup yield curve points.
	// NOTE: While the nested map does break convention, this enables us to quickly read, scan, and modify
	// lockup yield curve points without needing to traverse yield curve points held by other PKIDs.
	// This enables us to have a high performance means of computing yield during lockup transactions without
	// having to scan all yield curve points for all users stored in the view.
	PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints map[PKID]map[LockupYieldCurvePointKey]*LockupYieldCurvePoint

	// Current EpochEntry
	CurrentEpochEntry *EpochEntry

	// Current RandomSeedHash
	CurrentRandomSeedHash *RandomSeedHash

	// SnapshotGlobalParamEntries is a map of SnapshotAtEpochNumber to a GlobalParamsEntry.
	// It contains the snapshot value of the GlobalParamsEntry at the given SnapshotAtEpochNumber.
	SnapshotGlobalParamEntries map[uint64]*GlobalParamsEntry

	// SnapshotValidatorSet is a map of <SnapshotAtEpochNumber, ValidatorPKID> to a ValidatorEntry.
	// It contains the snapshot value of every ValidatorEntry that makes up the validator set at
	// the given SnapshotAtEpochNumber.
	SnapshotValidatorSet map[SnapshotValidatorSetMapKey]*ValidatorEntry

	// SnapshotValidatorBLSPublicKeyPKIDPairEntries is a map of <SnapshotAtEpochNumber, bls.SerializedPublicKey>
	// to a BLSPublicKeyPKIDPairEntry. It contains the snapshot value of the BLSPublicKeyPKIDPairEntry
	// of every validator that makes up the validator set at the given SnapshotAtEpochNumber.
	SnapshotValidatorBLSPublicKeyPKIDPairEntries map[SnapshotValidatorBLSPublicKeyMapKey]*BLSPublicKeyPKIDPairEntry

	// SnapshotValidatorSetTotalStakeAmountNanos is a map of SnapshotAtEpochNumber to the sum TotalStakeAmountNanos
	// for the validator set of for an epoch.
	// It contains the snapshot value of the GlobalActiveStakeAmountNanos at the given SnapshotAtEpochNumber.
	SnapshotValidatorSetTotalStakeAmountNanos map[uint64]*uint256.Int

	// SnapshotLeaderSchedule is a map of <SnapshotAtEpochNumber, LeaderIndex> to a ValidatorPKID.
	// It contains the PKID of the validator at the given index in the leader schedule
	// generated at the given SnapshotAtEpochNumber.
	SnapshotLeaderSchedule map[SnapshotLeaderScheduleMapKey]*PKID

	// SnapshotStakesToReward is a map of <SnapshotAtEpochNumber, ValidatorPKID, StakerPKID>
	// to a snapshotted StakeEntry for the ValidatorPKID and StakerPKID pair at a given SnapshotAtEpochNumber.
	SnapshotStakesToReward map[SnapshotStakeMapKey]*StakeEntry

	// The hash of the tip the view is currently referencing. Mainly used
	// for error-checking when doing a bulk operation on the view.
	TipHash *BlockHash

	// Handle is a pointer to the badger database. This is the primary data store
	// for entries and messages on the DeSo blockchain.
	Handle *badger.DB

	// Postgres is a pointer to the Postgres database. This is an alternative data store
	// to the badger database that has previously been used.
	Postgres *Postgres

	// DeSoParams is a struct that contains all of the parameters that
	// define how the DeSo blockchain operates. It is set once at startup
	// and then never changed.
	Params *DeSoParams

	// Snapshot tracks the current state of the hypersyncing database.
	Snapshot *Snapshot
	// EventManager is used to emit callbacks when certain actions are triggered.
	EventManager *EventManager
}

// Assumes the db Handle is already set on the view, but otherwise the
// initialization is full.
func (bav *UtxoView) _ResetViewMappingsAfterFlush() {
	// Utxo data
	bav.UtxoKeyToUtxoEntry = make(map[UtxoKey]*UtxoEntry)
	// TODO: Deprecate this value
	bav.NumUtxoEntries = GetUtxoNumEntries(bav.Handle, bav.Snapshot)
	bav.PublicKeyToDeSoBalanceNanos = make(map[PublicKey]uint64)

	// BitcoinExchange data
	bav.NanosPurchased = DbGetNanosPurchased(bav.Handle, bav.Snapshot)
	bav.USDCentsPerBitcoin = DbGetUSDCentsPerBitcoinExchangeRate(bav.Handle, bav.Snapshot)
	bav.GlobalParamsEntry = DbGetGlobalParamsEntry(bav.Handle, bav.Snapshot)
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

	// Messaging group entries
	bav.MessagingGroupKeyToMessagingGroupEntry = make(map[MessagingGroupKey]*MessagingGroupEntry)

	// Access group entries
	bav.AccessGroupIdToAccessGroupEntry = make(map[AccessGroupId]*AccessGroupEntry)
	bav.AccessGroupMembershipKeyToAccessGroupMember = make(map[AccessGroupMembershipKey]*AccessGroupMemberEntry)

	// Group chat and Dm messages.
	bav.GroupChatMessagesIndex = make(map[GroupChatMessageKey]*NewMessageEntry)
	bav.DmMessagesIndex = make(map[DmMessageKey]*NewMessageEntry)

	// Group chat and Dm threads.
	bav.DmThreadIndex = make(map[DmThreadKey]*DmThreadEntry)

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

	// Creator Coin Balance Entries
	bav.HODLerPKIDCreatorPKIDToBalanceEntry = make(map[BalanceEntryMapKey]*BalanceEntry)

	// DAO Coin Balance Entries
	bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry = make(map[BalanceEntryMapKey]*BalanceEntry)

	// Derived Key entries
	bav.DerivedKeyToDerivedEntry = make(map[DerivedKeyMapKey]*DerivedKeyEntry)

	// DAO Coin Limit Order Entries
	bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry = make(map[DAOCoinLimitOrderMapKey]*DAOCoinLimitOrderEntry)

	// Association entries
	bav.AssociationMapKeyToUserAssociationEntry = make(map[AssociationMapKey]*UserAssociationEntry)
	bav.AssociationMapKeyToPostAssociationEntry = make(map[AssociationMapKey]*PostAssociationEntry)

	// Transaction nonce map
	bav.TransactorNonceMapKeyToTransactorNonceEntry = make(map[TransactorNonceMapKey]*TransactorNonceEntry)

	// Locked Balance Entries Map
	bav.LockedBalanceEntryKeyToLockedBalanceEntry = make(map[LockedBalanceEntryKey]*LockedBalanceEntry)

	// Lockup Yield Curve Points Map
	bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints = make(map[PKID]map[LockupYieldCurvePointKey]*LockupYieldCurvePoint)

	// ValidatorEntries
	bav.ValidatorPKIDToValidatorEntry = make(map[PKID]*ValidatorEntry)
	// Validator BLS PublicKey to PKID
	bav.ValidatorBLSPublicKeyPKIDPairEntries = make(map[bls.SerializedPublicKey]*BLSPublicKeyPKIDPairEntry)

	// StakeEntries
	bav.StakeMapKeyToStakeEntry = make(map[StakeMapKey]*StakeEntry)

	// LockedStakeEntries
	bav.LockedStakeMapKeyToLockedStakeEntry = make(map[LockedStakeMapKey]*LockedStakeEntry)

	// CurrentEpochEntry
	bav.CurrentEpochEntry = nil

	// SnapshotGlobalParamEntries
	bav.SnapshotGlobalParamEntries = make(map[uint64]*GlobalParamsEntry)

	// SnapshotValidatorSet
	bav.SnapshotValidatorSet = make(map[SnapshotValidatorSetMapKey]*ValidatorEntry)

	// SnapshotValidatorBLSPublicKeyPKIDPairEntries
	bav.SnapshotValidatorBLSPublicKeyPKIDPairEntries = make(map[SnapshotValidatorBLSPublicKeyMapKey]*BLSPublicKeyPKIDPairEntry)

	// SnapshotValidatorSetTotalStakeAmountNanos
	bav.SnapshotValidatorSetTotalStakeAmountNanos = make(map[uint64]*uint256.Int)

	// SnapshotLeaderSchedule
	bav.SnapshotLeaderSchedule = make(map[SnapshotLeaderScheduleMapKey]*PKID)

	// SnapshotStakesToReward
	bav.SnapshotStakesToReward = make(map[SnapshotStakeMapKey]*StakeEntry)
}

func (bav *UtxoView) CopyUtxoView() (*UtxoView, error) {
	newView, err := NewUtxoView(bav.Handle, bav.Params, bav.Postgres, bav.Snapshot, bav.EventManager)
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

	// Copy access group entries
	newView.AccessGroupIdToAccessGroupEntry = make(map[AccessGroupId]*AccessGroupEntry, len(bav.AccessGroupIdToAccessGroupEntry))
	for key, entry := range bav.AccessGroupIdToAccessGroupEntry {
		newEntry := *entry
		newView.AccessGroupIdToAccessGroupEntry[key] = &newEntry
	}

	// Copy access group membership index
	newView.AccessGroupMembershipKeyToAccessGroupMember = make(map[AccessGroupMembershipKey]*AccessGroupMemberEntry, len(bav.AccessGroupMembershipKeyToAccessGroupMember))
	for key, member := range bav.AccessGroupMembershipKeyToAccessGroupMember {
		newMember := *member
		newView.AccessGroupMembershipKeyToAccessGroupMember[key] = &newMember
	}

	// Copy postgres message map
	newView.MessageMap = make(map[BlockHash]*PGMessage, len(bav.MessageMap))
	for txnHash, message := range bav.MessageMap {
		newMessage := *message
		newView.MessageMap[txnHash] = &newMessage
	}

	// Copy messaging group data
	newView.MessagingGroupKeyToMessagingGroupEntry = make(map[MessagingGroupKey]*MessagingGroupEntry, len(bav.MessagingGroupKeyToMessagingGroupEntry))
	for pkid, entry := range bav.MessagingGroupKeyToMessagingGroupEntry {
		newEntry := *entry
		newView.MessagingGroupKeyToMessagingGroupEntry[pkid] = &newEntry
	}

	// DM and Group chats
	// Copy group chat message index
	newView.GroupChatMessagesIndex = make(map[GroupChatMessageKey]*NewMessageEntry)
	for gcMsgKey, messageEntry := range bav.GroupChatMessagesIndex {
		newMessage := *messageEntry
		newView.GroupChatMessagesIndex[gcMsgKey] = &newMessage
	}

	// Copy dm messages index
	newView.DmMessagesIndex = make(map[DmMessageKey]*NewMessageEntry)
	for dmMessageKey, messageEntry := range bav.DmMessagesIndex {
		newMessage := *messageEntry
		newView.DmMessagesIndex[dmMessageKey] = &newMessage
	}

	// Copy dm thread index
	newView.DmThreadIndex = make(map[DmThreadKey]*DmThreadEntry)
	for dmThreadKey, threadEntry := range bav.DmThreadIndex {
		newThreadEntry := *threadEntry
		newView.DmThreadIndex[dmThreadKey] = &newThreadEntry
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

	// Copy the creator coin balance entry data
	newView.HODLerPKIDCreatorPKIDToBalanceEntry = make(
		map[BalanceEntryMapKey]*BalanceEntry, len(bav.HODLerPKIDCreatorPKIDToBalanceEntry))
	for balanceEntryMapKey, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		if balanceEntry == nil {
			continue
		}

		newBalanceEntry := *balanceEntry
		newView.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryMapKey] = &newBalanceEntry
	}

	// Copy the DAO coin balance entry data
	newView.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry = make(
		map[BalanceEntryMapKey]*BalanceEntry, len(bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry))
	for daoBalanceEntryMapKey, daoBalanceEntry := range bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry {
		if daoBalanceEntry == nil {
			continue
		}

		newDAOBalanceEntry := *daoBalanceEntry
		newView.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry[daoBalanceEntryMapKey] = &newDAOBalanceEntry
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

	// Copy the DAO Coin Limit Order Entries
	newView.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry = make(map[DAOCoinLimitOrderMapKey]*DAOCoinLimitOrderEntry,
		len(bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry))
	for entryKey, entry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		newEntry := *entry
		newView.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry[entryKey] = &newEntry
	}

	// Copy the Association entries
	newView.AssociationMapKeyToUserAssociationEntry = make(map[AssociationMapKey]*UserAssociationEntry, len(bav.AssociationMapKeyToUserAssociationEntry))
	for entryKey, entry := range bav.AssociationMapKeyToUserAssociationEntry {
		newEntry := *entry
		newView.AssociationMapKeyToUserAssociationEntry[entryKey] = &newEntry
	}
	newView.AssociationMapKeyToPostAssociationEntry = make(map[AssociationMapKey]*PostAssociationEntry, len(bav.AssociationMapKeyToPostAssociationEntry))
	for entryKey, entry := range bav.AssociationMapKeyToPostAssociationEntry {
		newEntry := *entry
		newView.AssociationMapKeyToPostAssociationEntry[entryKey] = &newEntry
	}

	// Copy the nonce map
	newView.TransactorNonceMapKeyToTransactorNonceEntry = make(map[TransactorNonceMapKey]*TransactorNonceEntry,
		len(bav.TransactorNonceMapKeyToTransactorNonceEntry))
	for entryKey, entry := range bav.TransactorNonceMapKeyToTransactorNonceEntry {
		newEntry := *entry
		newView.TransactorNonceMapKeyToTransactorNonceEntry[entryKey] = &newEntry
	}

	// Copy the LockedBalanceEntries
	newView.LockedBalanceEntryKeyToLockedBalanceEntry = make(map[LockedBalanceEntryKey]*LockedBalanceEntry,
		len(bav.LockedBalanceEntryKeyToLockedBalanceEntry))
	for entryKey, entry := range bav.LockedBalanceEntryKeyToLockedBalanceEntry {
		newView.LockedBalanceEntryKeyToLockedBalanceEntry[entryKey] = entry.Copy()
	}

	// Copy the LockupYieldCurvePoints
	newView.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints =
		make(map[PKID]map[LockupYieldCurvePointKey]*LockupYieldCurvePoint, len(bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints))
	for pkid, lockupYieldCurvePointMap := range bav.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints {
		// Copy the map for the given PKID
		newView.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[pkid] =
			make(map[LockupYieldCurvePointKey]*LockupYieldCurvePoint, len(lockupYieldCurvePointMap))

		// Go through all LockupYieldCurvePoints in the LockupYieldCurvePoint map.
		for entryKey, entry := range lockupYieldCurvePointMap {
			newView.PKIDToLockupYieldCurvePointKeyToLockupYieldCurvePoints[pkid][entryKey] = entry.Copy()
		}
	}

	// Copy the ValidatorEntries
	newView.ValidatorPKIDToValidatorEntry = make(map[PKID]*ValidatorEntry, len(bav.ValidatorPKIDToValidatorEntry))
	for entryKey, entry := range bav.ValidatorPKIDToValidatorEntry {
		newView.ValidatorPKIDToValidatorEntry[entryKey] = entry.Copy()
	}

	// Copy the validator BLS PublicKey to PKID map
	newView.ValidatorBLSPublicKeyPKIDPairEntries = make(map[bls.SerializedPublicKey]*BLSPublicKeyPKIDPairEntry, len(bav.ValidatorBLSPublicKeyPKIDPairEntries))
	for entryKey, entry := range bav.ValidatorBLSPublicKeyPKIDPairEntries {
		newView.ValidatorBLSPublicKeyPKIDPairEntries[entryKey] = entry.Copy()
	}

	// Copy the StakeEntries
	newView.StakeMapKeyToStakeEntry = make(map[StakeMapKey]*StakeEntry, len(bav.StakeMapKeyToStakeEntry))
	for entryKey, entry := range bav.StakeMapKeyToStakeEntry {
		newView.StakeMapKeyToStakeEntry[entryKey] = entry.Copy()
	}

	// Copy the LockedStakeEntries
	newView.LockedStakeMapKeyToLockedStakeEntry = make(
		map[LockedStakeMapKey]*LockedStakeEntry, len(bav.LockedStakeMapKeyToLockedStakeEntry),
	)
	for entryKey, entry := range bav.LockedStakeMapKeyToLockedStakeEntry {
		newView.LockedStakeMapKeyToLockedStakeEntry[entryKey] = entry.Copy()
	}

	// Copy the CurrentEpochEntry
	if bav.CurrentEpochEntry != nil {
		newView.CurrentEpochEntry = bav.CurrentEpochEntry.Copy()
	}

	// Copy the CurrentRandomSeedHash
	if bav.CurrentRandomSeedHash != nil {
		newView.CurrentRandomSeedHash = bav.CurrentRandomSeedHash.Copy()
	}

	// Copy the SnapshotGlobalParamEntries
	for epochNumber, globalParamsEntry := range bav.SnapshotGlobalParamEntries {
		newView.SnapshotGlobalParamEntries[epochNumber] = globalParamsEntry.Copy()
	}

	// Copy the SnapshotValidatorSet
	for mapKey, validatorEntry := range bav.SnapshotValidatorSet {
		newView.SnapshotValidatorSet[mapKey] = validatorEntry.Copy()
	}

	for mapKey, blsPublicKeyPKIDPairEntry := range bav.SnapshotValidatorBLSPublicKeyPKIDPairEntries {
		newView.SnapshotValidatorBLSPublicKeyPKIDPairEntries[mapKey] = blsPublicKeyPKIDPairEntry.Copy()
	}

	// Copy the SnapshotValidatorSetTotalStakeAmountNanos
	for epochNumber, totalStakeAmountNanos := range bav.SnapshotValidatorSetTotalStakeAmountNanos {
		newView.SnapshotValidatorSetTotalStakeAmountNanos[epochNumber] = totalStakeAmountNanos.Clone()
	}

	// Copy the SnapshotLeaderSchedule
	for mapKey, validatorPKID := range bav.SnapshotLeaderSchedule {
		newView.SnapshotLeaderSchedule[mapKey] = validatorPKID.NewPKID()
	}

	// Copy the SnapshotStakesToReward
	for mapKey, snapshotStakeToReward := range bav.SnapshotStakesToReward {
		newView.SnapshotStakesToReward[mapKey] = snapshotStakeToReward.Copy()
	}

	return newView, nil
}

func NewUtxoView(
	_handle *badger.DB,
	_params *DeSoParams,
	_postgres *Postgres,
	_snapshot *Snapshot,
	_eventManager *EventManager,
) (*UtxoView, error) {

	view := UtxoView{
		Handle: _handle,
		Params: _params,
		// Note that the TipHash does not get reset as part of
		// _ResetViewMappingsAfterFlush because it is not something that is affected by a
		// flush operation. Moreover, its value is consistent with the view regardless of
		// whether the view is flushed or not. Additionally, the utxo view does not concern
		// itself with the header chain (see comment on GetBestHash for more info on that).
		TipHash: DbGetBestHash(_handle, _snapshot, ChainTypeDeSoBlock /* don't get the header chain */),

		Postgres:     _postgres,
		Snapshot:     _snapshot,
		EventManager: _eventManager,
		// Set everything else in _ResetViewMappings()
	}

	// Note that the TipHash does not get reset as part of
	// _ResetViewMappingsAfterFlush because it is not something that is affected by a
	// flush operation. Moreover, its value is consistent with the view regardless of
	// whether or not the view is flushed or not. Additionally the utxo view does
	// not concern itself with the header chain (see comment on GetBestHash for more
	// info on that).
	if view.Postgres != nil {
		pgChain := view.Postgres.GetChain(MAIN_CHAIN)
		if pgChain != nil {
			view.TipHash = view.Postgres.GetChain(MAIN_CHAIN).TipHash
		}
	} else {
		view.TipHash = DbGetBestHash(view.Handle, view.Snapshot, ChainTypeDeSoBlock /* don't get the header chain */)
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

func (bav *UtxoView) GetUtxoEntryForUtxoKey(utxoKeyArg *UtxoKey) *UtxoEntry {
	utxoKey := &UtxoKey{}
	if utxoKeyArg != nil {
		*utxoKey = *utxoKeyArg
	}

	utxoEntry, ok := bav.UtxoKeyToUtxoEntry[*utxoKey]
	// If the utxo entry isn't in our in-memory data structure, fetch it from the
	// db.
	if !ok {
		if bav.Postgres != nil {
			utxoEntry = bav.Postgres.GetUtxoEntryForUtxoKey(utxoKey)
		} else {
			utxoEntry = DbGetUtxoEntryForUtxoKey(bav.Handle, bav.Snapshot, utxoKey)
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

func (bav *UtxoView) GetDeSoBalanceNanosForPublicKey(publicKeyArg []byte) (uint64, error) {
	if publicKeyArg == nil {
		return 0, errors.New("GetDeSoBalanceNanosForPublicKey: Called with nil publicKeyArg")
	}
	if len(publicKeyArg) != btcec.PubKeyBytesLenCompressed {
		return 0, fmt.Errorf("GetDeSoBalanceNanosForPublicKey: Called with "+
			"publicKeyArg of length %d but expected length %d",
			len(publicKeyArg), btcec.PubKeyBytesLenCompressed)
	}
	publicKey := publicKeyArg

	balanceNanos, hasBalance := bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(publicKey)]
	if hasBalance {
		return balanceNanos, nil
	}

	var err error
	balanceNanos, err = bav.GetDbAdapter().GetDeSoBalanceForPublicKey(publicKey)
	if err != nil {
		return 0, errors.Wrapf(err,
			"GetDeSoBalanceNanosForPublicKey: Problem getting balance for public key %v",
			PkToString(publicKey, bav.Params))
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

func (bav *UtxoView) _spendUtxo(utxoKeyArg *UtxoKey) (*UtxoOperation, error) {
	// Swap this utxo's position with the utxo in the last position and delete it.
	utxoKey := &UtxoKey{}
	if utxoKeyArg != nil {
		*utxoKey = *utxoKeyArg
	}

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

func (bav *UtxoView) _addBalance(amountNanos uint64, balancePublicKey []byte,
) (*UtxoOperation, error) {
	if len(balancePublicKey) == 0 {
		return nil, fmt.Errorf("_addBalance: balancePublicKey must be non-empty")
	}
	// Get the current balance and then update it on the view.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(balancePublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_addBalance: ")
	}
	desoBalanceNanos, err = SafeUint64().Add(desoBalanceNanos, amountNanos)
	if err != nil {
		return nil, errors.Wrapf(err, "_addBalance: add %d nanos to balance %d for public key %s: ", amountNanos, desoBalanceNanos, PkToStringBoth(balancePublicKey))
	}
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(balancePublicKey)] = desoBalanceNanos

	// Finally record a UtxoOperation in case we want to roll back this ADD
	// in the future. Note that Entry data isn't required for an ADD operation.
	return &UtxoOperation{
		Type:               OperationTypeAddBalance,
		BalancePublicKey:   balancePublicKey,
		BalanceAmountNanos: amountNanos,
	}, nil
}

func (bav *UtxoView) _addBalanceForStakeReward(amountNanos uint64, balancePublicKey []byte,
) (*UtxoOperation, error) {
	utxoOp, err := bav._addBalance(amountNanos, balancePublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_addBalanceForStakeReward: ")
	}
	utxoOp.Type = OperationTypeStakeDistributionPayToBalance
	return utxoOp, nil
}

func (bav *UtxoView) _addDESO(amountNanos uint64, publicKey []byte, utxoEntry *UtxoEntry, blockHeight uint32,
) (*UtxoOperation, error) {
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight {
		return bav._addBalance(amountNanos, publicKey)
	}
	return bav._addUtxo(utxoEntry)
}

func (bav *UtxoView) _unAddBalance(amountNanos uint64, balancePublicKey []byte) error {
	// Get the current balance and then remove the added balance.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(balancePublicKey)
	if err != nil {
		return errors.Wrapf(err, "_unAddBalance: ")
	}
	desoBalanceNanos, err = SafeUint64().Sub(desoBalanceNanos, amountNanos)
	if err != nil {
		return fmt.Errorf("_unAddBalance: amount to unAdd (%d) exceeds balance (%d) for public key %s",
			amountNanos, desoBalanceNanos, PkToStringBoth(balancePublicKey))
	}
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(balancePublicKey)] = desoBalanceNanos

	return nil
}

func (bav *UtxoView) _spendBalance(
	amountNanos uint64, balancePublicKey []byte, tipHeight uint32,
) (*UtxoOperation, error) {
	// First we must check that the public key has sufficient spendable balance.
	spendableBalanceNanos, err :=
		bav.GetSpendableDeSoBalanceNanosForPublicKey(balancePublicKey, tipHeight)
	if err != nil {
		return nil, errors.Wrapf(err, "_spendBalance: ")
	}
	if spendableBalanceNanos < amountNanos {
		return nil, errors.Wrapf(RuleErrorInsufficientBalance,
			"_spendBalance: amountNanos (%d) exceeds spendable balance (%d) at tipHeight (%d)",
			amountNanos, spendableBalanceNanos, tipHeight,
		)
	}
	if len(balancePublicKey) == 0 {
		return nil, fmt.Errorf(" no pub key provided")
	}

	// Now that we know we can spend amountNanos, get the current balance and spend it.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(balancePublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_spendBalance: ")
	}
	desoBalanceNanos, err = SafeUint64().Sub(desoBalanceNanos, amountNanos)
	if err != nil {
		return nil, errors.Wrapf(RuleErrorInsufficientBalance,
			"_spendBalance: amountNanos (%d) exceeds deso balance (%d) for public key %s - this should never happen, %v",
			amountNanos, desoBalanceNanos, PkToStringBoth(balancePublicKey), err)
	}
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(balancePublicKey)] = desoBalanceNanos

	// Finally record a UtxoOperation in case we want to roll back this ADD
	// in the future. Note that Entry data isn't required for an ADD operation.
	return &UtxoOperation{
		Type:               OperationTypeSpendBalance,
		BalancePublicKey:   balancePublicKey,
		BalanceAmountNanos: amountNanos,
	}, nil
}

func (bav *UtxoView) _unSpendBalance(amountNanos uint64, balancePublicKey []byte) error {
	// Get the current balance and add back the spent amountNanos.
	desoBalanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(balancePublicKey)
	if err != nil {
		return errors.Wrapf(err, "_unSpendBalance: ")
	}
	desoBalanceNanos, err = SafeUint64().Add(desoBalanceNanos, amountNanos)
	if err != nil {
		return errors.Wrapf(err,
			"_unSpendBalance: adding %d nanos to balance %d for public key %s",
			amountNanos, desoBalanceNanos, balancePublicKey)
	}
	bav.PublicKeyToDeSoBalanceNanos[*NewPublicKey(balancePublicKey)] = desoBalanceNanos

	return nil
}

func (bav *UtxoView) _disconnectBasicTransfer(currentTxn *MsgDeSoTxn, txnHash *BlockHash, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {
	// First we check to see if we're passed the derived key spending limit block height.
	// If we are, search for a spending limit accounting operation. If one exists, we disconnect
	// the accounting changes and decrement the operation index to move past it.
	operationIndex := len(utxoOpsForTxn) - 1
	if blockHeight >= bav.Params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight {
		if len(utxoOpsForTxn) > 0 && utxoOpsForTxn[operationIndex].Type == OperationTypeSpendingLimitAccounting {
			currentOperation := utxoOpsForTxn[operationIndex]
			// Get the current derived key entry
			derivedPkBytes, isDerived, err := IsDerivedSignature(currentTxn, blockHeight)
			if !isDerived || err != nil {
				return fmt.Errorf("_disconnectBasicTransfer: Found Spending Limit Accounting op with non-derived "+
					"key signature or got an error %v", err)
			}
			if err := IsByteArrayValidPublicKey(derivedPkBytes); err != nil {
				return fmt.Errorf(
					"_disconnectBasicTransfer: %v is not a valid public key: %v",
					PkToString(derivedPkBytes, bav.Params),
					err)
			}
			derivedKeyEntry := bav.GetDerivedKeyMappingForOwner(currentTxn.PublicKey, derivedPkBytes)
			if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
				return fmt.Errorf("_disconnectBasicTransfer: could not find derived key entry")
			}

			// Delete the derived key entry mapping and re-add it if the previous mapping is not nil.
			bav._deleteDerivedKeyMapping(derivedKeyEntry)
			if currentOperation.PrevDerivedKeyEntry != nil {
				bav._setDerivedKeyMapping(currentOperation.PrevDerivedKeyEntry)
			}
			operationIndex--
		}
	}

	// Next, we check to see if the last utxoOp (either last one in the list or last one before the spending limit
	// account op) was a diamond operation. If it was, we disconnect the diamond-related changes and decrement
	// the operation index to move past it.
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

	// If this is a balance model basic transfer, the disconnect is simplified.  We first
	// loop over the outputs and subtract the amounts from each recipient's balance, then
	// we add the spent DESO + txn fees back to the sender's balance. In the balance model
	// no UTXOs are stored so outputs do not need to be looked up or deleted.
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight {
		for outputIndex := len(currentTxn.TxOutputs) - 1; outputIndex >= 0; outputIndex-- {
			currentOutput := currentTxn.TxOutputs[outputIndex]
			if err := bav._unAddBalance(currentOutput.AmountNanos, currentOutput.PublicKey); err != nil {
				return errors.Wrapf(err, "_disconnectBasicTransfer: Problem unAdding output %v: ", currentOutput)
			}
		}
		// Block reward transactions don't unspend DESO since it is newly created DESO
		// and no input DESO was provided.
		if currentTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
			// Iterate over utxo ops and unspend any balance that was spent by the transactor.
			for _, utxoOp := range utxoOpsForTxn {
				if utxoOp.Type != OperationTypeSpendBalance ||
					!bytes.Equal(utxoOp.BalancePublicKey, currentTxn.PublicKey) {
					continue
				}
				if err := bav._unSpendBalance(utxoOp.BalanceAmountNanos, currentTxn.PublicKey); err != nil {
					return errors.Wrapf(err,
						"_disconnectBasicTransfer: Problem unSpending balance of %v for transactor: ",
						utxoOp.BalanceAmountNanos)
				}
			}
		}
		return nil
	}
	// If this is a UTXO model basic transfer, then loop through the transaction's
	// outputs backwards and remove them from the view. Since the outputs will have
	// been added to the view at the end of the utxo list, removing them from the
	// view amounts to removing the last element from the utxo list.
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

func (bav *UtxoView) DisconnectTransaction(currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Start by resetting the expected nonce for this txn's public key.
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight && currentTxn.TxnMeta.GetTxnType() != TxnTypeBlockReward {

		// Make sure we haven't seen the nonce yet
		pkidEntry := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
		if pkidEntry == nil || pkidEntry.isDeleted {
			return fmt.Errorf("DisconnectTransaction: PKID for public key %s does not exist", PkToString(currentTxn.PublicKey, bav.Params))
		}
		nonce, err := bav.GetTransactorNonceEntry(currentTxn.TxnNonce, pkidEntry.PKID)
		if err != nil {
			return errors.Wrapf(err, "DisconnectTransaction: Problem getting account nonce for nonce %s and PKID %v", currentTxn.TxnNonce.String(), pkidEntry.PKID)
		}
		if nonce == nil || nonce.isDeleted {
			return fmt.Errorf("DisconnectTransaction: Nonce %s hasn't been seen for PKID %v", currentTxn.TxnNonce.String(), pkidEntry.PKID)
		}
		bav.DeleteTransactorNonceEntry(nonce)
	}

	switch currentTxn.TxnMeta.GetTxnType() {
	case TxnTypeBlockReward, TxnTypeBasicTransfer:
		return bav._disconnectBasicTransfer(
			currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeBitcoinExchange:
		return bav._disconnectBitcoinExchange(
			OperationTypeBitcoinExchange, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypePrivateMessage:
		return bav._disconnectPrivateMessage(
			OperationTypePrivateMessage, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeMessagingGroup:
		return bav._disconnectMessagingGroup(
			OperationTypeMessagingKey, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeSubmitPost:
		return bav._disconnectSubmitPost(
			OperationTypeSubmitPost, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUpdateProfile:
		return bav._disconnectUpdateProfile(
			OperationTypeUpdateProfile, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUpdateBitcoinUSDExchangeRate:
		return bav._disconnectUpdateBitcoinUSDExchangeRate(
			OperationTypeUpdateBitcoinUSDExchangeRate, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUpdateGlobalParams:
		return bav._disconnectUpdateGlobalParams(
			OperationTypeUpdateGlobalParams, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeFollow:
		return bav._disconnectFollow(
			OperationTypeFollow, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeLike:
		return bav._disconnectLike(
			OperationTypeLike, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeCreatorCoin:
		return bav._disconnectCreatorCoin(
			OperationTypeCreatorCoin, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeCreatorCoinTransfer:
		return bav._disconnectCreatorCoinTransfer(
			OperationTypeCreatorCoinTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeDAOCoin:
		return bav._disconnectDAOCoin(
			OperationTypeDAOCoin, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeDAOCoinTransfer:
		return bav._disconnectDAOCoinTransfer(
			OperationTypeDAOCoinTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeDAOCoinLimitOrder:
		return bav._disconnectDAOCoinLimitOrder(
			OperationTypeDAOCoinLimitOrder, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeSwapIdentity:
		return bav._disconnectSwapIdentity(
			OperationTypeSwapIdentity, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeCreateNFT:
		return bav._disconnectCreateNFT(
			OperationTypeCreateNFT, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUpdateNFT:
		return bav._disconnectUpdateNFT(
			OperationTypeUpdateNFT, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeAcceptNFTBid:
		return bav._disconnectAcceptNFTBid(
			OperationTypeAcceptNFTBid, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeNFTBid:
		return bav._disconnectNFTBid(
			OperationTypeNFTBid, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeNFTTransfer:
		return bav._disconnectNFTTransfer(
			OperationTypeNFTTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeAcceptNFTTransfer:
		return bav._disconnectAcceptNFTTransfer(
			OperationTypeAcceptNFTTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeBurnNFT:
		return bav._disconnectBurnNFT(
			OperationTypeBurnNFT, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeAuthorizeDerivedKey:
		return bav._disconnectAuthorizeDerivedKey(
			OperationTypeAuthorizeDerivedKey, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	case TxnTypeCreateUserAssociation:
		return bav._disconnectCreateUserAssociation(
			OperationTypeCreateUserAssociation, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeDeleteUserAssociation:
		return bav._disconnectDeleteUserAssociation(
			OperationTypeDeleteUserAssociation, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeCreatePostAssociation:
		return bav._disconnectCreatePostAssociation(
			OperationTypeCreatePostAssociation, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeDeletePostAssociation:
		return bav._disconnectDeletePostAssociation(
			OperationTypeDeletePostAssociation, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeAccessGroup:
		return bav._disconnectAccessGroup(
			OperationTypeAccessGroup, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeAccessGroupMembers:
		return bav._disconnectAccessGroupMembers(
			OperationTypeAccessGroupMembers, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeNewMessage:
		return bav._disconnectNewMessage(
			OperationTypeNewMessage, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeRegisterAsValidator:
		return bav._disconnectRegisterAsValidator(
			OperationTypeRegisterAsValidator, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUnregisterAsValidator:
		return bav._disconnectUnregisterAsValidator(
			OperationTypeUnregisterAsValidator, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeStake:
		return bav._disconnectStake(
			OperationTypeStake, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUnstake:
		return bav._disconnectUnstake(
			OperationTypeUnstake, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUnlockStake:
		return bav._disconnectUnlockStake(
			OperationTypeUnlockStake, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeUnjailValidator:
		return bav._disconnectUnjailValidator(
			OperationTypeUnjailValidator, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	case TxnTypeCoinLockup:
		return bav._disconnectCoinLockup(OperationTypeCoinLockup, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	case TxnTypeUpdateCoinLockupParams:
		return bav._disconnectUpdateCoinLockupParams(
			OperationTypeUpdateCoinLockupParams, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	case TxnTypeCoinLockupTransfer:
		return bav._disconnectCoinLockupTransfer(
			OperationTypeCoinLockupTransfer, currentTxn, txnHash, utxoOpsForTxn, blockHeight)
	case TxnTypeCoinUnlock:
		return bav._disconnectCoinUnlock(OperationTypeCoinUnlock, currentTxn, txnHash, utxoOpsForTxn, blockHeight)

	}

	return fmt.Errorf("DisconnectBlock: Unimplemented txn type %v", currentTxn.TxnMeta.GetTxnType().String())
}

func (bav *UtxoView) DisconnectBlock(
	desoBlock *MsgDeSoBlock, txHashes []*BlockHash, utxoOps [][]*UtxoOperation, blockHeight uint64) error {

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
	numAcceptNFTBidTxns := 0
	numDAOCoinLimitOrderTxns := 0
	for _, txn := range desoBlock.Txns {
		numInputs += len(txn.TxInputs)
		if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
			numInputs += len(txn.TxnMeta.(*AcceptNFTBidMetadata).BidderInputs)
			numAcceptNFTBidTxns++
		}
		if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoinLimitOrder {
			numDAOCoinLimitOrderTxns++
			numMatchingOrderInputs := 0

			for _, transactor := range txn.TxnMeta.(*DAOCoinLimitOrderMetadata).BidderInputs {
				numMatchingOrderInputs += len(transactor.Inputs)
			}

			numInputs += numMatchingOrderInputs
		}
		numOutputs += len(txn.TxOutputs)
	}
	numSpendUtxoOps := 0
	numAddUtxoOps := 0
	numAddToBalanceOps := 0
	numSpendBalanceOps := 0
	for _, utxoOpsForTxn := range utxoOps {
		for _, op := range utxoOpsForTxn {
			switch op.Type {
			case OperationTypeSpendUtxo:
				numSpendUtxoOps++
			case OperationTypeAddUtxo:
				numAddUtxoOps++
			case OperationTypeAddBalance:
				numAddToBalanceOps++
			case OperationTypeSpendBalance:
				numSpendBalanceOps++
			}
		}
	}
	if numInputs != numSpendUtxoOps {
		return fmt.Errorf(
			"DisconnectBlock: Number of inputs in passed block (%d) "+
				"not equal to number of SPEND operations in passed "+
				"utxoOps (%d)", numInputs, numSpendUtxoOps)
	}
	// Under the balance model, all txns should have one spend with the following exceptions:
	//    - Block rewards have no spend.
	//    - AcceptNFTBidTxns have 2 spends (one for the seller and one for the bidder).
	//    - DAOCoinLimitOrderTxns have n spends
	//    - Buy Now NFTs have 2 spends (one for the seller and one for the bidder).
	// TODO: this needs some checking
	// TODO: this condition is hard to satisfy w/ DAO coin limit orders since we don't have bidder inputs
	// specified.
	//if (len(desoBlock.Txns)-1)+numAcceptNFTBidTxns < numSpendBalanceOps &&
	//	desoBlock.Header.Height >= uint64(bav.Params.ForkHeights.BalanceModelBlockHeight) {
	//	return fmt.Errorf(
	//		"DisconnectBlock: Expected number of spend operations in passed block (%d) "+
	//			"is less than the number of SPEND BALANCE operations in passed "+
	//			"utxoOps (%d)", len(desoBlock.Txns)-1, numSpendBalanceOps)
	//}
	// Note that the number of add operations can be greater than the number of "explicit"
	// outputs in the block because transactions like BitcoinExchange
	// produce "implicit" outputs when the transaction is applied.
	if numOutputs > numAddUtxoOps && desoBlock.Header.Height < uint64(bav.Params.ForkHeights.BalanceModelBlockHeight) {
		return fmt.Errorf(
			"DisconnectBlock: Number of outputs in passed block (%d) "+
				"not equal to number of ADD operations in passed "+
				"utxoOps (%d)", numOutputs, numAddUtxoOps)
	}

	if numOutputs > numAddToBalanceOps && desoBlock.Header.Height >= uint64(bav.Params.ForkHeights.BalanceModelBlockHeight) {
		return fmt.Errorf(
			"DisconnectBlock: Number of outputs in passed block (%d) "+
				"not equal to number of ADD TO BALANCE operations in passed "+
				"utxoOps (%d)", numOutputs, numAddUtxoOps)
	}

	// After the balance model block height, we may have a delete expired nonces utxo operation.
	// We need to revert this before iterating over the transactions in the block.
	// After the proof of stake fork height, we may have utxo operations for stake distributions.
	// Stake distribution UtxoOps may be either an AddBalance or a StakeDistribution operation type.
	// We need to revert these before iterating over the transactions in the block.
	if desoBlock.Header.Height >= uint64(bav.Params.ForkHeights.BalanceModelBlockHeight) {
		if len(utxoOps) != len(desoBlock.Txns)+1 {
			return fmt.Errorf(
				"DisconnectBlock: Expected number of utxo ops to be equal to number of txns in block plus one for"+
					" delete expired nonces operation for block %d",
				desoBlock.Header.Height)
		}
		var isLastBlockInEpoch bool
		isLastBlockInEpoch, err = bav.IsLastBlockInCurrentEpoch(desoBlock.Header.Height)
		if err != nil {
			return errors.Wrapf(err, "DisconnectBlock: Problem checking if block is last in epoch")
		}
		blockLevelUtxoOps := utxoOps[len(utxoOps)-1]
		for ii := len(blockLevelUtxoOps) - 1; ii >= 0; ii-- {
			utxoOp := blockLevelUtxoOps[ii]
			switch utxoOp.Type {
			case OperationTypeDeleteExpiredNonces:
				// We need to revert the delete expired nonces operation.
				for _, nonceEntry := range utxoOp.PrevNonceEntries {
					bav.SetTransactorNonceEntry(nonceEntry)
				}
			case OperationTypeStakeDistributionPayToBalance:
				// We don't allow add balance utxo operations unless it's the end of an epoch.
				if !isLastBlockInEpoch {
					return fmt.Errorf("DisconnectBlock: Found add balance operation in block %d that is not the end "+
						"of an epoch", desoBlock.Header.Height)
				}
				// We need to revert the add balance operation.
				if err = bav._unAddBalance(utxoOp.BalanceAmountNanos, utxoOp.BalancePublicKey); err != nil {
					return errors.Wrapf(err, "DisconnectBlock: Problem unAdding balance %v: ", utxoOp.BalanceAmountNanos)
				}
			case OperationTypeStakeDistributionRestake:
				// We don't allow stake distribution utxo operations unless it's the end of an epoch.
				if !isLastBlockInEpoch {
					return fmt.Errorf("DisconnectBlock: Found add balance operation in block %d that is not the end "+
						"of an epoch", desoBlock.Header.Height)
				}
				if len(utxoOp.PrevStakeEntries) != 1 {
					return fmt.Errorf("DisconnectBlock: Expected exactly one prev stake entry for stake distribution op")
				}
				if utxoOp.PrevValidatorEntry == nil {
					return fmt.Errorf("DisconnectBlock: Expected prev validator entry for stake distribution op")
				}
				bav._setStakeEntryMappings(utxoOp.PrevStakeEntries[0])
				bav._setValidatorEntryMappings(utxoOp.PrevValidatorEntry)
			case OperationTypeSetValidatorLastActiveAtEpoch:
				if utxoOp.PrevValidatorEntry == nil {
					return fmt.Errorf("DisconnectBlock: Expected prev validator entry for set validator last active " +
						"at epoch op")
				}
				bav._setValidatorEntryMappings(utxoOp.PrevValidatorEntry)
			}
		}
	}

	// Loop through the txns backwards to process them.
	// Track the operation we're performing as we go.
	for txnIndex := len(desoBlock.Txns) - 1; txnIndex >= 0; txnIndex-- {
		currentTxn := desoBlock.Txns[txnIndex]
		txnHash := txHashes[txnIndex]
		utxoOpsForTxn := utxoOps[txnIndex]
		desoBlockHeight := desoBlock.Header.Height

		if err = bav.DisconnectTransaction(currentTxn, txnHash, utxoOpsForTxn, uint32(desoBlockHeight)); err != nil {
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

func (bav *UtxoView) VerifySignature(txn *MsgDeSoTxn, blockHeight uint32) (_derivedPkBytes []byte, _err error) {
	return bav._verifySignature(txn, blockHeight)
}

func (bav *UtxoView) _verifySignature(txn *MsgDeSoTxn, blockHeight uint32) (_derivedPkBytes []byte, _err error) {
	if txn.Signature.Sign == nil {
		return nil, fmt.Errorf("_verifySignature: Transaction signature is empty")
	}
	if blockHeight >= bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
		if txn.Signature.HasHighS() {
			return nil, errors.Wrapf(RuleErrorTxnSigHasHighS, "_verifySignature: high-S deteceted")
		}
	}
	// Compute a hash of the transaction.
	txBytes, err := txn.ToBytes(true /*preSignature*/)
	if err != nil {
		return nil, errors.Wrapf(err, "_verifySignature: Problem serializing txn without signature: ")
	}
	txHash := Sha256DoubleHash(txBytes)

	// Look for the derived key in transaction ExtraData and validate it. For transactions
	// signed using a derived key, the derived public key is passed in ExtraData. Alternatively,
	// if the signature uses DeSo-DER encoding, meaning we can recover the derived public key from
	// the signature.
	var derivedPk *btcec.PublicKey
	derivedPkBytes, isDerived, err := IsDerivedSignature(txn, blockHeight)
	if err != nil {
		return nil, errors.Wrapf(err, "_verifySignature: Something went wrong while checking for "+
			"derived key signature")
	}
	// If we got a derived key then try parsing it.
	if isDerived {
		derivedPk, err = btcec.ParsePubKey(derivedPkBytes, btcec.S256())
		if err != nil {
			return nil, fmt.Errorf("%v %v", RuleErrorDerivedKeyInvalidExtraData, RuleErrorDerivedKeyInvalidRecoveryId)
		}
	}

	// Get the owner public key and attempt turning it into *btcec.PublicKey.
	ownerPkBytes := txn.PublicKey
	ownerPk, err := btcec.ParsePubKey(ownerPkBytes, btcec.S256())
	if err != nil {
		return nil, errors.Wrapf(err, "_verifySignature: Problem parsing owner public key: ")
	}

	// If no derived key was used, we check if transaction was signed by the owner.
	// If derived key *was* used, we check if transaction was signed by the derived key.
	if derivedPk == nil {
		// Verify that the transaction is signed by the specified key.
		if txn.Signature.Verify(txHash[:], ownerPk) {
			return nil, nil
		}
	} else {
		// Look for a derived key entry in UtxoView and DB, check to make sure it exists and is not isDeleted.
		if err := bav.ValidateDerivedKey(ownerPkBytes, derivedPkBytes, uint64(blockHeight)); err != nil {
			return nil, err
		}

		// All checks passed so we try to verify the signature. This step can be avoided for DeSo-DER signatures
		// but we run it redundantly just in case.
		if txn.Signature.Verify(txHash[:], derivedPk) {
			return derivedPk.SerializeCompressed(), nil
		}

		return nil, errors.Wrapf(RuleErrorDerivedKeyNotAuthorized, "Signature check failed: ")
	}

	return nil, RuleErrorInvalidTransactionSignature
}

// ValidateDerivedKey checks if a derived key is authorized and valid.
func (bav *UtxoView) ValidateDerivedKey(ownerPkBytes []byte, derivedPkBytes []byte, blockHeight uint64) error {
	derivedKeyEntry := bav.GetDerivedKeyMappingForOwner(ownerPkBytes, derivedPkBytes)
	if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
		return errors.Wrapf(RuleErrorDerivedKeyNotAuthorized, "Derived key mapping for owner not found: Owner: %v, "+
			"Derived key: %v", PkToStringBoth(ownerPkBytes), PkToStringBoth(derivedPkBytes))
	}

	// Sanity-check that transaction public keys line up with looked-up derivedKeyEntry public keys.
	if !reflect.DeepEqual(ownerPkBytes, derivedKeyEntry.OwnerPublicKey[:]) ||
		!reflect.DeepEqual(derivedPkBytes, derivedKeyEntry.DerivedPublicKey[:]) {
		return errors.Wrapf(RuleErrorDerivedKeyNotAuthorized, "DB entry (OwnerPubKey, DerivedPubKey) = (%v, %v) does not "+
			"match keys used to look up the entry: (%v, %v). This should never happen.",
			PkToStringBoth(derivedKeyEntry.OwnerPublicKey[:]), PkToStringBoth(derivedKeyEntry.DerivedPublicKey[:]),
			PkToStringBoth(ownerPkBytes), PkToStringBoth(derivedPkBytes))
	}

	// At this point, we know the derivedKeyEntry that we have is matching.
	// We check if the derived key hasn't been de-authorized or hasn't expired.
	if derivedKeyEntry.OperationType != AuthorizeDerivedKeyOperationValid ||
		derivedKeyEntry.ExpirationBlock <= blockHeight {
		return errors.Wrapf(RuleErrorDerivedKeyNotAuthorized, "Derived key EITHER deactivated or block height expired. "+
			"Deactivation status: %v, Expiration block height: %v, Current block height: %v",
			derivedKeyEntry.OperationType, derivedKeyEntry.ExpirationBlock, blockHeight)
	}

	// If we get to this point, we got a valid derived key.
	return nil
}

// IsDerivedSignature checks if a transaction was signed using a derived key. If so, it will recover the derived key used
// to sign the transaction. There are two possible ways to serialize transaction's ECDSA signature for a derived key.
// Either to use the DER encoding and place the derived public key in transaction's ExtraData, or to use DeSo-DER signature
// encoding and pass a special recovery ID into the signature's bytes. However, both encodings can't be used at the same time.
func IsDerivedSignature(txn *MsgDeSoTxn, blockHeight uint32) (_derivedPkBytes []byte, _isDerived bool, _err error) {
	if MigrationTriggered(uint64(blockHeight), AssociationsAndAccessGroupsMigration) {
		if txn.Signature.HasHighS() {
			return nil, false, errors.Wrapf(
				RuleErrorTxnSigHasHighS,
				"IsDerivedSignature: signature has high s")
		}
	}
	// If transaction contains ExtraData, then check if the DerivedPublicKey was passed along.
	if txn.ExtraData != nil {
		derivedPkBytes, isDerived := txn.ExtraData[DerivedPublicKey]
		// Make sure both encodings aren't used concurrently.
		if isDerived && txn.Signature.IsRecoverable {
			return nil, false, errors.Wrapf(RuleErrorDerivedKeyHasBothExtraDataAndRecoveryId,
				"IsDerivedSignature: transaction signed with a derived key can either store public key in "+
					"ExtraData or use the DeSo-DER recoverable signature encoding but not BOTH")
		}
		if isDerived {
			return derivedPkBytes, isDerived, nil
		}
	}

	// If transaction doesn't contain a derived key in ExtraData, then check if it contains the recovery ID.
	if txn.Signature.IsRecoverable {
		// Assemble the transaction hash; we need it in order to recover the public key.
		txBytes, err := txn.ToBytes(true /*preSignature*/)
		if err != nil {
			return nil, false, errors.Wrapf(err, "IsDerivedSignature: Problem "+
				"serializing txn without signature: ")
		}
		txHash := Sha256DoubleHash(txBytes)[:]

		// Recover the public key from the signature.
		derivedPublicKey, err := txn.Signature.RecoverPublicKey(txHash)
		if err != nil {
			return nil, false, errors.Wrapf(err, "IsDerivedSignature: Problem recovering "+
				"public key from signature")
		}
		return derivedPublicKey.SerializeCompressed(), true, nil
	}
	return nil, false, nil

}

func (bav *UtxoView) _connectBasicTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	uint64, uint64, []*UtxoOperation, error) {
	return bav._connectBasicTransferWithExtraSpend(txn, txHash, blockHeight, 0, verifySignatures)
}

func (bav *UtxoView) _connectBasicTransferWithExtraSpend(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, extraSpend uint64, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	var utxoOpsForTxn []*UtxoOperation

	// Loop through all the inputs and validate them.
	var totalInput uint64
	// After the BalanceModelBlockHeight, UTXO inputs are no longer allowed.
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight && len(txn.TxInputs) != 0 {
		return 0, 0, nil, RuleErrorBalanceModelDoesNotUseUTXOInputs
	}
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
			glog.V(1).Infof("utxoKey: %v, utxoEntry: %v, height: %d", &utxoKey, utxoEntry, blockHeight)
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
			return 0, 0, nil, errors.Wrapf(
				RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey,
				"utxoEntry.PublicKey: %v, txn.PublicKey: %v, "+
					"utxoEntry.UtxoKey: %v:%v, AmountNanos: %v",
				PkToStringTestnet(utxoEntry.PublicKey),
				PkToStringTestnet(txn.PublicKey),
				hex.EncodeToString(utxoEntry.UtxoKey.TxID[:]),
				utxoEntry.UtxoKey.Index, utxoEntry.AmountNanos)
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
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend Problem spending input utxo")
		}

		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	if len(txn.TxInputs) != len(utxoEntriesForInputs) {
		// Something went wrong if these lists differ in length.
		return 0, 0, nil, fmt.Errorf("_connectBasicTransferWithExtraSpend Length of list of " +
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

	// At this point, all the utxos corresponding to inputs of this txn
	// should be marked as spent in the view. Now we go through and process
	// the outputs.
	var totalOutput uint64
	amountsByPublicKey := make(map[PublicKey]uint64)
	utxoEntries := []UtxoEntry{}
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
		currentAmount, _ := amountsByPublicKey[*NewPublicKey(desoOutput.PublicKey)]
		amountsByPublicKey[*NewPublicKey(desoOutput.PublicKey)] = currentAmount + desoOutput.AmountNanos

		// A basic transfer cannot create any output other than a "normal" output
		// or a BlockReward. Outputs of other types must be created after processing
		// the "basic" outputs.

		// If we have transitioned to balance model, we need to add to the total input
		// as we will spend the total output before adding DESO for the outputs.
		if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight &&
			txn.TxnMeta.GetTxnType() != TxnTypeBlockReward {

			var err error
			totalInput, err = SafeUint64().Add(totalInput, desoOutput.AmountNanos)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err,
					"_connectBasicTransferWithExtraSpend: Problem adding "+
						"output amount %v to total input %v: %v", desoOutput.AmountNanos, totalInput, err)
			}
		}

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

		utxoEntries = append(utxoEntries, UtxoEntry{
			AmountNanos: desoOutput.AmountNanos,
			PublicKey:   desoOutput.PublicKey,
			BlockHeight: blockHeight,
			UtxoType:    utxoType,
			UtxoKey:     &outputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		})
	}

	// After the BalanceModelBlockHeight, we no longer spend UTXO inputs. Instead, we must
	// spend the sender's balance. Note that we don't need to explicitly check that the
	// sender's balance is sufficient because _spendBalance will error if it is insufficient.
	// Note that for block reward transactions, we don't spend any balance; DESO is printed.
	// If we have transitioned to the balance model, then always attempt to spend
	// the output from the transactor's balance before adding it to the recipient's
	// balance. This ensures we never enter situations where we are calling _addDeSo
	// before we call _spendBalance to verify that the transactor has the coins.
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight &&
		txn.TxnMeta.GetTxnType() != TxnTypeBlockReward {

		var err error
		feePlusExtraSpend := txn.TxnFeeNanos
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend Problem adding txn fee and total output")
		}
		feePlusExtraSpend, err = SafeUint64().Add(feePlusExtraSpend, extraSpend)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend Problem adding extraSpend")
		}

		totalInput, err = SafeUint64().Add(totalInput, feePlusExtraSpend)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err,
				"_connectBasicTransferWithExtraSpend: Problem adding "+
					"amount %v to total input %v: %v", feePlusExtraSpend, totalInput, err)
		}
		// When spending balances, we need to check for immature block rewards. Since we don't have
		// the block rewards yet for the current block, we subtract one from the current block height
		// when spending balances.
		newUtxoOp, err := bav._spendBalance(totalInput, txn.PublicKey, blockHeight-1)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_connectBasicTransferWithExtraSpend Problem spending balance")
		}
		utxoOpsForTxn = append(utxoOpsForTxn, newUtxoOp)
	}

	// Now that we've constructed the utxo entries for each output and spent the
	// transactor's balance to pay for all of them, we can call _addDeSo safely.
	for _, utxoEntry := range utxoEntries {
		// If we have a problem adding this utxo or balance return an error but don't
		// mark this block as invalid since it's not a rule error and the block
		// could therefore benefit from being processed in the future.
		newUtxoOp, err := bav._addDESO(utxoEntry.AmountNanos, utxoEntry.PublicKey, &utxoEntry, blockHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend Problem adding DESO")
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
	if hasDiamondPostHash && blockHeight > bav.Params.ForkHeights.DeSoDiamondsBlockHeight &&
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
				"_connectBasicTransferWithExtraSpend DiamondPostHashBytes length: %d", len(diamondPostHashBytes))
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
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend ")
		}
		diamondRecipientTotal, _ := amountsByPublicKey[*NewPublicKey(diamondRecipientPubKey)]

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
		if err := bav._verifyTxnSignature(txn, blockHeight); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend ")
		}
	}

	if blockHeight >= bav.Params.ForkHeights.DerivedKeyTrackSpendingLimitsBlockHeight {
		if derivedPkBytes, isDerivedSig, err := IsDerivedSignature(txn, blockHeight); isDerivedSig {
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectBasicTransferWithExtraSpend "+
					"It looks like this transaction was signed with a derived key, but the signature is malformed: ")
			}
			// Now we check the transaction limits on the derived key.
			// At this point we know that the transaction was signed by a derived key and the signature passes validation
			// against the provided derived key. We will now verify that the spending limit for this derived key allows for
			// this transaction, and error otherwise. If everything checks out, we will update the spending limit for this
			// derived key to reflect the new spending limit after the transaction has been performed.
			utxoOpsForTxn, err = bav._checkAndUpdateDerivedKeySpendingLimit(txn, derivedPkBytes, totalInput, utxoOpsForTxn, blockHeight)
			if err != nil {
				return 0, 0, nil, err
			}
		}
	}

	// Now that we've processed the transaction, return all of the computed
	// data.
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _verifyTxnSignature(txn *MsgDeSoTxn, blockHeight uint32) error {
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
		if len(txn.PublicKey) != 0 || txn.Signature.Sign != nil {
			return RuleErrorBlockRewardTxnNotAllowedToHaveSignature
		}
	} else {
		if _, err := bav._verifySignature(txn, blockHeight); err != nil {
			return errors.Wrapf(err, "_connectBasicTransferWithExtraSpend Problem verifying txn signature: ")
		}
	}
	return nil
}

func (bav *UtxoView) _checkAndUpdateDerivedKeySpendingLimit(
	txn *MsgDeSoTxn, derivedPkBytes []byte, totalInput uint64, utxoOpsForTxn []*UtxoOperation, blockHeight uint32) (
	_utxoOpsForTxn []*UtxoOperation, _err error) {

	// Get the derived key entry
	prevDerivedKeyEntry := bav.GetDerivedKeyMappingForOwner(txn.PublicKey, derivedPkBytes)
	if prevDerivedKeyEntry == nil || prevDerivedKeyEntry.isDeleted {
		return utxoOpsForTxn, fmt.Errorf("_checkAndUpdateDerivedKeySpendingLimit: No derived key entry found")
	}

	// Create a copy of the prevDerivedKeyEntry so we can safely modify the new entry
	derivedKeyEntry := *prevDerivedKeyEntry.Copy()
	// Make sure spending limit is not nil.
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil {
		return utxoOpsForTxn, errors.Wrap(RuleErrorDerivedKeyNotAuthorized,
			"_checkAndUpdateDerivedKeySpendingLimit: TransactionSpendingLimitTracker is nil")
	}
	// If the derived key is an unlimited key, we don't need to further check nor update the spending limits whatsoever.
	if derivedKeyEntry.TransactionSpendingLimitTracker.IsUnlimited {
		return utxoOpsForTxn, nil
	}

	// Spend amount is total inputs minus sum of AddUtxo type operations
	// going to transactor (i.e. change).
	//
	// Note the following edge cases whereby this check will potentially not protect
	// the user:
	// - For TxnTypeNFTBid, a bid can be placed on someone's NFT without triggering this
	//   check. The user should be extra careful when approving an NFT bid, making sure
	//   that the amount being bid *and* the NFT being bid on are accurate.
	// - For TxnTypeCreatorCoinTransfer, the app can transfer as much creator coin as it
	//   wants without hitting this check.
	// - For TxnTypeDAOCoinTransfer, same as the TxnTypeCreatorCoinTransfer.
	// - For TxnTypeCreatorCoin, a SELL operation could liquidate someone's creator
	//   coin without triggering this check.
	//
	// These are all acceptable, as the main point of this check is to prevent someone's
	// money being spent when attempting non-monetary txns like SubmitPost or Follow.
	spendAmount := totalInput
	for _, utxoOp := range utxoOpsForTxn {
		if utxoOp.Type == OperationTypeAddUtxo && utxoOp.Entry.UtxoType == UtxoTypeOutput &&
			reflect.DeepEqual(utxoOp.Entry.PublicKey, txn.PublicKey) {
			if utxoOp.Entry.AmountNanos > spendAmount {
				return utxoOpsForTxn, fmt.Errorf("_checkAndUpdateDerivedKeySpendingLimit: Underflow on spend amount")
			}
			spendAmount -= utxoOp.Entry.AmountNanos
		}
		if utxoOp.Type == OperationTypeAddBalance &&
			reflect.DeepEqual(utxoOp.BalancePublicKey, txn.PublicKey) {

			if utxoOp.BalanceAmountNanos > spendAmount {
				return utxoOpsForTxn, fmt.Errorf("_checkAndUpdateDerivedKeySpendingLimit: Underflow on spend amount")
			}
			spendAmount -= utxoOp.BalanceAmountNanos
		}
	}

	// If the spend amount exceeds the Global DESO limit, this derived key is not authorized to spend this DESO.
	if spendAmount > derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit {
		return utxoOpsForTxn, errors.Wrapf(RuleErrorDerivedKeyTxnSpendsMoreThanGlobalDESOLimit,
			"_checkAndUpdateDerivedKeySpendingLimit: Spend Amount %v Exceeds Global DESO Limit %v for Derived Key",
			spendAmount, spew.Sdump(derivedKeyEntry.TransactionSpendingLimitTracker))
	}

	// Decrement the global limit by the spend amount
	derivedKeyEntry.TransactionSpendingLimitTracker.GlobalDESOLimit -= spendAmount

	txnType := txn.TxnMeta.GetTxnType()

	var err error
	// Okay now we've validated that we can do the op. Decrement the special counters if applicable
	switch txnType {
	case TxnTypeCreatorCoin:
		txnMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
		var creatorCoinLimitOperation CreatorCoinLimitOperation
		switch txnMeta.OperationType {
		case CreatorCoinOperationTypeBuy:
			creatorCoinLimitOperation = BuyCreatorCoinOperation
		case CreatorCoinOperationTypeSell:
			creatorCoinLimitOperation = SellCreatorCoinOperation
		default:
			return utxoOpsForTxn, errors.Wrapf(
				RuleErrorDerivedKeyInvalidCreatorCoinLimitOperation,
				"_checkAndUpdateDerivedKeySpendingLimit: Invalid creator coin limit operation %v",
				txnMeta.OperationType)
		}
		if derivedKeyEntry, err = bav._checkCreatorCoinLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.ProfilePublicKey, creatorCoinLimitOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeCreatorCoinTransfer:
		txnMeta := txn.TxnMeta.(*CreatorCoinTransferMetadataa)
		if derivedKeyEntry, err = bav._checkCreatorCoinLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.ProfilePublicKey, TransferCreatorCoinOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeDAOCoin:
		txnMeta := txn.TxnMeta.(*DAOCoinMetadata)
		var daoCoinLimitOperation DAOCoinLimitOperation
		switch txnMeta.OperationType {
		case DAOCoinOperationTypeMint:
			daoCoinLimitOperation = MintDAOCoinOperation
		case DAOCoinOperationTypeBurn:
			daoCoinLimitOperation = BurnDAOCoinOperation
		case DAOCoinOperationTypeDisableMinting:
			daoCoinLimitOperation = DisableMintingDAOCoinOperation
		case DAOCoinOperationTypeUpdateTransferRestrictionStatus:
			daoCoinLimitOperation = UpdateTransferRestrictionStatusDAOCoinOperation
		default:
			return utxoOpsForTxn, errors.Wrapf(
				RuleErrorDerivedKeyInvalidDAOCoinLimitOperation,
				"_checkAndUpdateDerivedKeySpendingLimit: Invalid DAO coin limit operation %v",
				txnMeta.OperationType)
		}
		if derivedKeyEntry, err = bav._checkDAOCoinLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.ProfilePublicKey, daoCoinLimitOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeDAOCoinTransfer:
		txnMeta := txn.TxnMeta.(*DAOCoinTransferMetadata)
		if derivedKeyEntry, err = bav._checkDAOCoinLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.ProfilePublicKey, TransferDAOCoinOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeDAOCoinLimitOrder:
		txnMeta := txn.TxnMeta.(*DAOCoinLimitOrderMetadata)
		var buyingCoinPublicKey []byte
		var sellingCoinPublicKey []byte
		if txnMeta.CancelOrderID != nil {
			orderEntry, err := bav._getDAOCoinLimitOrderEntry(txnMeta.CancelOrderID)
			if err != nil || orderEntry == nil {
				return utxoOpsForTxn, errors.Wrapf(
					RuleErrorDerivedKeyInvalidDAOCoinLimitOrderOrderID,
					"_checkAndUpdateDerivedKeySpendingLimit: Invalid DAO coin limit order ID %v",
					txnMeta.CancelOrderID)
			}
			buyingCoinPublicKey = bav.GetPublicKeyForPKID(orderEntry.BuyingDAOCoinCreatorPKID)
			sellingCoinPublicKey = bav.GetPublicKeyForPKID(orderEntry.SellingDAOCoinCreatorPKID)
		} else {
			buyingCoinPublicKey = txnMeta.BuyingDAOCoinCreatorPublicKey.ToBytes()
			sellingCoinPublicKey = txnMeta.SellingDAOCoinCreatorPublicKey.ToBytes()
		}
		if derivedKeyEntry, err = bav._checkDAOCoinLimitOrderLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, buyingCoinPublicKey, sellingCoinPublicKey); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeUpdateNFT:
		txnMeta := txn.TxnMeta.(*UpdateNFTMetadata)
		if derivedKeyEntry, err = _checkNFTLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.NFTPostHash, txnMeta.SerialNumber, UpdateNFTOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeAcceptNFTBid:
		txnMeta := txn.TxnMeta.(*AcceptNFTBidMetadata)
		if derivedKeyEntry, err = _checkNFTLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.NFTPostHash, txnMeta.SerialNumber, AcceptNFTBidOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeNFTBid:
		txnMeta := txn.TxnMeta.(*NFTBidMetadata)
		if derivedKeyEntry, err = _checkNFTLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.NFTPostHash, txnMeta.SerialNumber, NFTBidOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeAcceptNFTTransfer:
		txnMeta := txn.TxnMeta.(*AcceptNFTTransferMetadata)
		if derivedKeyEntry, err = _checkNFTLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.NFTPostHash, txnMeta.SerialNumber, AcceptNFTTransferOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeNFTTransfer:
		txnMeta := txn.TxnMeta.(*NFTTransferMetadata)
		if derivedKeyEntry, err = _checkNFTLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.NFTPostHash, txnMeta.SerialNumber, TransferNFTOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeBurnNFT:
		txnMeta := txn.TxnMeta.(*BurnNFTMetadata)
		if derivedKeyEntry, err = _checkNFTLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta.NFTPostHash, txnMeta.SerialNumber, BurnNFTOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeCreateUserAssociation:
		txnMeta := txn.TxnMeta.(*CreateUserAssociationMetadata)
		if derivedKeyEntry, err = bav._checkAssociationLimitAndUpdateDerivedKey(
			derivedKeyEntry,
			AssociationClassUser,
			txnMeta.AssociationType,
			txnMeta.AppPublicKey,
			AssociationOperationCreate,
		); err != nil {
			return utxoOpsForTxn, errors.Wrapf(err, "_checkDerivedKeySpendingLimit: ")
		}
	case TxnTypeDeleteUserAssociation:
		txnMeta := txn.TxnMeta.(*DeleteUserAssociationMetadata)
		associationEntry, err := bav.GetUserAssociationByID(txnMeta.AssociationID)
		if err != nil {
			return utxoOpsForTxn, errors.Wrapf(err, "_checkDerivedKeySpendingLimit: ")
		}
		if associationEntry == nil {
			return utxoOpsForTxn, errors.New("_checkDerivedKeySpendingLimit: association to delete not found")
		}
		if derivedKeyEntry, err = bav._checkAssociationLimitAndUpdateDerivedKey(
			derivedKeyEntry,
			AssociationClassUser,
			associationEntry.AssociationType,
			NewPublicKey(bav.GetPublicKeyForPKID(associationEntry.AppPKID)),
			AssociationOperationDelete,
		); err != nil {
			return utxoOpsForTxn, errors.Wrapf(err, "_checkDerivedKeySpendingLimit: ")
		}
	case TxnTypeCreatePostAssociation:
		var associationType []byte
		var appPublicKey *PublicKey
		if blockHeight >= bav.Params.ForkHeights.AssociationsDerivedKeySpendingLimitBlockHeight {
			txnMeta := txn.TxnMeta.(*CreatePostAssociationMetadata)
			associationType = txnMeta.AssociationType
			appPublicKey = txnMeta.AppPublicKey
		} else {
			txnMeta := txn.TxnMeta.(*CreateUserAssociationMetadata)
			associationType = txnMeta.AssociationType
			appPublicKey = txnMeta.AppPublicKey
		}
		if derivedKeyEntry, err = bav._checkAssociationLimitAndUpdateDerivedKey(
			derivedKeyEntry,
			AssociationClassPost,
			associationType,
			appPublicKey,
			AssociationOperationCreate,
		); err != nil {
			return utxoOpsForTxn, errors.Wrapf(err, "_checkDerivedKeySpendingLimit: ")
		}
	case TxnTypeDeletePostAssociation:
		txnMeta := txn.TxnMeta.(*DeletePostAssociationMetadata)
		associationEntry, err := bav.GetPostAssociationByID(txnMeta.AssociationID)
		if err != nil {
			return utxoOpsForTxn, errors.Wrapf(err, "_checkDerivedKeySpendingLimit: ")
		}
		if associationEntry == nil {
			return utxoOpsForTxn, errors.New("_checkDerivedKeySpendingLimit: association to delete not found")
		}
		if derivedKeyEntry, err = bav._checkAssociationLimitAndUpdateDerivedKey(
			derivedKeyEntry,
			AssociationClassPost,
			associationEntry.AssociationType,
			NewPublicKey(bav.GetPublicKeyForPKID(associationEntry.AppPKID)),
			AssociationOperationDelete,
		); err != nil {
			return utxoOpsForTxn, errors.Wrapf(err, "_checkDerivedKeySpendingLimit: ")
		}
	case TxnTypeAccessGroup:
		txnMeta := txn.TxnMeta.(*AccessGroupMetadata)
		if derivedKeyEntry, err = bav._checkAccessGroupSpendingLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeAccessGroupMembers:
		txnMeta := txn.TxnMeta.(*AccessGroupMembersMetadata)
		if derivedKeyEntry, err = bav._checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry(
			derivedKeyEntry, txnMeta); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeCoinLockup:
		txnMeta := txn.TxnMeta.(*CoinLockupMetadata)
		if derivedKeyEntry, err = bav._checkLockupTxnSpendingLimitAndUpdateDerivedKey(
			derivedKeyEntry, txnMeta.ProfilePublicKey, CoinLockupOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeUpdateCoinLockupParams:
		txnUpdatesYieldCurve := false
		txnUpdatesTransferRestrictions := false
		// NOTE: While this breaks convention, we allow the UpdateCoinLockupParamsMetadata to decrement
		//       two different derived key limits independently for added flexibility. We could
		//       have a limit as to the number of UpdateCoinLockupParams transactions but given the
		//       importance of security regarding the lockup yield curve it makes more sense to break
		//       derived key limits for UpdateCoinLockupParams into multiple behavior specific limits.
		txnMeta := txn.TxnMeta.(*UpdateCoinLockupParamsMetadata)
		// Check if we're updating the transactor's yield curve.
		// NOTE: It's described in a longer comment in UpdateCoinLockupParamsMetadata that if
		//       LockupYieldDurationNanoSecs is zero, the other fields associated with updating
		//       the yield curve are ignored. Hence, the check below checks that any update
		//       to the yield curve exists in the given transaction.
		if txnMeta.LockupYieldDurationNanoSecs > 0 {
			txnUpdatesYieldCurve = true
			if derivedKeyEntry, err = bav._checkLockupTxnSpendingLimitAndUpdateDerivedKey(
				derivedKeyEntry, NewPublicKey(txn.PublicKey), UpdateCoinLockupYieldCurveOperation); err != nil {
				return utxoOpsForTxn, err
			}
		}
		// Check if we're updating the transactor's transfer restrictions.
		if txnMeta.NewLockupTransferRestrictions {
			txnUpdatesTransferRestrictions = true
			if derivedKeyEntry, err = bav._checkLockupTxnSpendingLimitAndUpdateDerivedKey(
				derivedKeyEntry, NewPublicKey(txn.PublicKey), UpdateCoinLockupTransferRestrictionsOperation); err != nil {
				return utxoOpsForTxn, err
			}
		}
		// Throw an error if this transaction does nothing. A derived key transaction should decrement
		// at least one limit as otherwise it's spending fees and accomplishing nothing.
		if !txnUpdatesYieldCurve && !txnUpdatesTransferRestrictions {
			return utxoOpsForTxn, RuleErrorDerivedKeyUpdateCoinLockupParamsIsNoOp
		}
	case TxnTypeCoinLockupTransfer:
		txnMeta := txn.TxnMeta.(*CoinLockupTransferMetadata)
		if derivedKeyEntry, err = bav._checkLockupTxnSpendingLimitAndUpdateDerivedKey(
			derivedKeyEntry, txnMeta.ProfilePublicKey, CoinLockupTransferOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeCoinUnlock:
		txnMeta := txn.TxnMeta.(*CoinUnlockMetadata)
		if derivedKeyEntry, err = bav._checkLockupTxnSpendingLimitAndUpdateDerivedKey(
			derivedKeyEntry, txnMeta.ProfilePublicKey, CoinLockupUnlockOperation); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeStake:
		txnMeta := txn.TxnMeta.(*StakeMetadata)
		if derivedKeyEntry, err = bav._checkStakeTxnSpendingLimitAndUpdateDerivedKey(
			derivedKeyEntry, txn.PublicKey, txnMeta); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeUnstake:
		txnMeta := txn.TxnMeta.(*UnstakeMetadata)
		if derivedKeyEntry, err = bav._checkUnstakeTxnSpendingLimitAndUpdateDerivedKey(
			derivedKeyEntry, txnMeta); err != nil {
			return utxoOpsForTxn, err
		}
	case TxnTypeUnlockStake:
		txnMeta := txn.TxnMeta.(*UnlockStakeMetadata)
		if derivedKeyEntry, err = bav._checkUnlockStakeTxnSpendingLimitAndUpdateDerivedKey(
			derivedKeyEntry, txnMeta); err != nil {
			return utxoOpsForTxn, err
		}
	default:
		// If we get here, it means we're dealing with a txn that doesn't have any special
		// granular limits to deal with. This means we just check whether we have
		// quota to execute this particular TxnType.
		if derivedKeyEntry.TransactionSpendingLimitTracker.TransactionCountLimitMap == nil {
			return utxoOpsForTxn, errors.Wrapf(RuleErrorDerivedKeyNotAuthorized,
				"_checkAndUpdateDerivedKeySpendingLimit: TransactionCountLimitMap is nil")
		}
		// If the transaction limit is not specified or equal to 0, this derived
		// key is not authorized to perform this transaction.
		transactionLimit, transactionLimitExists :=
			derivedKeyEntry.TransactionSpendingLimitTracker.TransactionCountLimitMap[txnType]
		if !transactionLimitExists || transactionLimit == 0 {
			return utxoOpsForTxn, errors.Wrapf(
				RuleErrorDerivedKeyTxnTypeNotAuthorized,
				"_checkAndUpdateDerivedKeySpendingLimit: No more transactions of type %v are allowed on this Derived Key",
				txnType.String())
		}
		// Otherwise, this derived key is authorized to perform this operation. Delete the key if this is the last
		// time this derived key can perform this operation, otherwise decrement the counter.
		if transactionLimit == 1 {
			delete(derivedKeyEntry.TransactionSpendingLimitTracker.TransactionCountLimitMap, txnType)
		} else {
			derivedKeyEntry.TransactionSpendingLimitTracker.TransactionCountLimitMap[txnType]--
		}
	}
	// Set derived key entry mapping
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	// Append the SpendingLimitAccounting operation se can revert this transaction in the disconnect logic
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                OperationTypeSpendingLimitAccounting,
		PrevDerivedKeyEntry: prevDerivedKeyEntry,
	})
	return utxoOpsForTxn, nil
}

// _checkNFTKeyAndUpdateDerivedKeyEntry checks if the NFTOperationLimitKey is present
// in the DerivedKeyEntry's TransactionSpendingLimitTracker's NFTOperationLimitMap.
// If the key is present, the operation is allowed and we decrement the number of
// operations remaining. If there are no operation remaining after this one, we
// delete the key. Returns true if the key was found and the derived key entry
// was updated.
func _checkNFTKeyAndUpdateDerivedKeyEntry(key NFTOperationLimitKey, derivedKeyEntry DerivedKeyEntry) bool {
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.NFTOperationLimitMap == nil {
		return false
	}
	// If the key is present in the NFTOperationLimitMap...
	nftLimit, nftLimitExist := derivedKeyEntry.TransactionSpendingLimitTracker.NFTOperationLimitMap[key]
	// Return false because we didn't find the key
	if !nftLimitExist || nftLimit <= 0 {
		return false
	}
	// If this is the last operation allowed for this key, we delete the key from the map.
	if nftLimit == 1 {
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.NFTOperationLimitMap, key)
	} else {
		// Otherwise, we decrement the number of operations remaining for this key
		derivedKeyEntry.TransactionSpendingLimitTracker.NFTOperationLimitMap[key]--
	}
	// Return true because we found the key and decremented the remaining operations
	return true
}

func _checkNFTLimitAndUpdateDerivedKeyEntry(
	derivedKeyEntry DerivedKeyEntry, nftPostHash *BlockHash, serialNumber uint64, operation NFTLimitOperation) (
	_derivedKeyEntry DerivedKeyEntry, _err error) {
	// We allow you to set permissions on NFTs at multiple levels: Post hash, serial number,
	// operation type. In checking permissions, we start by trying to use up the quota from
	// the most specific possible combination, and then work our way up to the more general
	// combinations. This ensures that the quota is used most efficiently.

	// Start by checking (specific post hash || specific serial number || specific operation key)
	postHashSerialNumberOperationKey := MakeNFTOperationLimitKey(*nftPostHash, serialNumber, operation)
	if _checkNFTKeyAndUpdateDerivedKeyEntry(postHashSerialNumberOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (specific post hash || specific serial number || any operation key)
	postHashSerialNumberAnyOpKey := MakeNFTOperationLimitKey(*nftPostHash, serialNumber, AnyNFTOperation)
	if _checkNFTKeyAndUpdateDerivedKeyEntry(postHashSerialNumberAnyOpKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (specific post hash || any serial number (= 0 to check this) || specific operation key)
	postHashZeroSerialNumOperationKey := MakeNFTOperationLimitKey(*nftPostHash, 0, operation)
	if _checkNFTKeyAndUpdateDerivedKeyEntry(postHashZeroSerialNumOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (specific post hash || any serial number (= 0 to check this) || any operation key)
	postHashZeroSerialNumAnyOperationKey := MakeNFTOperationLimitKey(*nftPostHash, 0, AnyNFTOperation)
	if _checkNFTKeyAndUpdateDerivedKeyEntry(postHashZeroSerialNumAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next, check (any post hash || any serial number (= 0 to check this) || specific operation key)
	nilPostHashZeroSerialNumOperationKey := MakeNFTOperationLimitKey(ZeroBlockHash, 0, operation)
	if _checkNFTKeyAndUpdateDerivedKeyEntry(nilPostHashZeroSerialNumOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Lastly, check (any post hash || any serial number (= 0 to check this) || any operation key)
	nilPostHashZeroSerialNumAnyOperationKey := MakeNFTOperationLimitKey(ZeroBlockHash, 0, AnyNFTOperation)
	if _checkNFTKeyAndUpdateDerivedKeyEntry(nilPostHashZeroSerialNumAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Note we don't check nil post hash + serial number cases, because that
	// doesn't really make sense. Think about it.
	return derivedKeyEntry, RuleErrorDerivedKeyNFTOperationNotAuthorized
}

// _checkCreatorCoinKeyAndUpdateDerivedKeyEntry checks if the CreatorCoinOperationLimitKey is present
// in the DerivedKeyEntry's TransactionSpendingLimitTracker's CreatorCoinOperationLimitMap.
// If the key is present, the operation is allowed and we decrement the number of operation remaining.
// If there are no operation remaining after this one, we delete the key.
// Returns true if the key was found and the derived key entry was updated.
func _checkCreatorCoinKeyAndUpdateDerivedKeyEntry(key CreatorCoinOperationLimitKey, derivedKeyEntry DerivedKeyEntry) bool {
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap == nil {
		return false
	}
	// If the key is present in the CreatorCoinOperationLimitMap...
	ccOperationLimit, ccOperationLimitExists :=
		derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap[key]
	// Return false because we didn't find the key
	if !ccOperationLimitExists || ccOperationLimit <= 0 {
		return false
	}
	// If this is the last operation allowed for this key, we delete the key from the map.
	if ccOperationLimit == 1 {
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap, key)
	} else {
		// Otherwise, we decrement the number of operations remaining for this key
		derivedKeyEntry.TransactionSpendingLimitTracker.CreatorCoinOperationLimitMap[key]--
	}
	// Return true because we found the key and decremented the remaining operations
	return true
}

func (bav *UtxoView) _checkCreatorCoinLimitAndUpdateDerivedKeyEntry(
	derivedKeyEntry DerivedKeyEntry, creatorPublicKey []byte, operation CreatorCoinLimitOperation) (
	_derivedKeyEntry DerivedKeyEntry, _err error) {
	pkidEntry := bav.GetPKIDForPublicKey(creatorPublicKey)
	if pkidEntry == nil || pkidEntry.isDeleted {
		return derivedKeyEntry, fmt.Errorf(
			"_checkCreatorCoinLimitAndUpdateDerivedKeyEntry: creator pkid is deleted")
	}

	// First check (creator pkid || operation) key
	creatorOperationKey := MakeCreatorCoinOperationLimitKey(*pkidEntry.PKID, operation)
	if _checkCreatorCoinKeyAndUpdateDerivedKeyEntry(creatorOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (creator pkid || any operation) key
	creatorAnyOperationKey := MakeCreatorCoinOperationLimitKey(*pkidEntry.PKID, AnyCreatorCoinOperation)
	if _checkCreatorCoinKeyAndUpdateDerivedKeyEntry(creatorAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (any creator pkid || operation) key
	nilCreatorOperationKey := MakeCreatorCoinOperationLimitKey(ZeroPKID, operation)
	if _checkCreatorCoinKeyAndUpdateDerivedKeyEntry(nilCreatorOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Finally, check (any creator pkid || any operation) key
	nilCreatorAnyOperationKey := MakeCreatorCoinOperationLimitKey(ZeroPKID, AnyCreatorCoinOperation)
	if _checkCreatorCoinKeyAndUpdateDerivedKeyEntry(nilCreatorAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}
	return derivedKeyEntry, errors.Wrapf(RuleErrorDerivedKeyCreatorCoinOperationNotAuthorized,
		"_checkCreatorCoinLimitAndUpdateDerivedKeyEntry: cc operation not authorized: ")
}

// _checkDAOCoinKeyAndUpdateDerivedKeyEntry checks if the DAOCoinOperationLimitKey is present
// in the DerivedKeyEntry's TransactionSpendingLimitTracker's DAOCoinOperationLimitMap.
// If the key is present, the operation is allowed and we decrement the number of operation remaining.
// If there are no operation remaining after this one, we delete the key.
// Returns true if the key was found and the derived key entry was updated.
func _checkDAOCoinKeyAndUpdateDerivedKeyEntry(key DAOCoinOperationLimitKey, derivedKeyEntry DerivedKeyEntry) bool {
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinOperationLimitMap == nil {
		return false
	}
	// If the key is present in the DAOCoinOperationLimitMap...
	daoCoinOperationLimit, daoCoinOperationLimitExists :=
		derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinOperationLimitMap[key]
	// Return false because we didn't find the key
	if !daoCoinOperationLimitExists || daoCoinOperationLimit <= 0 {
		return false
	}
	// If this is the last operation allowed for this key, we delete the key from the map.
	if daoCoinOperationLimit == 1 {
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinOperationLimitMap, key)
	} else {
		// Otherwise, we decrement the number of operations remaining for this key
		derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinOperationLimitMap[key]--
	}
	// Return true because we found the key and decremented the remaining operations
	return true
}

// _checkDAOCoinLimitAndUpdateDerivedKeyEntry checks that the DAO coin operation being performed has
// been authorized for this derived key.
func (bav *UtxoView) _checkDAOCoinLimitAndUpdateDerivedKeyEntry(
	derivedKeyEntry DerivedKeyEntry, creatorPublicKey []byte, operation DAOCoinLimitOperation) (
	_derivedKeyEntry DerivedKeyEntry, _err error) {
	pkidEntry := bav.GetPKIDForPublicKey(creatorPublicKey)
	if pkidEntry == nil || pkidEntry.isDeleted {
		return derivedKeyEntry, fmt.Errorf("_checkDAOCoinLimitAndUpdateDerivedKeyEntry: creator pkid is deleted")
	}

	// First check (creator pkid || operation) key
	creatorOperationKey := MakeDAOCoinOperationLimitKey(*pkidEntry.PKID, operation)
	if _checkDAOCoinKeyAndUpdateDerivedKeyEntry(creatorOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (creator pkid || any operation) key
	creatorAnyOperationKey := MakeDAOCoinOperationLimitKey(*pkidEntry.PKID, AnyDAOCoinOperation)
	if _checkDAOCoinKeyAndUpdateDerivedKeyEntry(creatorAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Next check (any creator pkid || operation) key
	nilCreatorOperationKey := MakeDAOCoinOperationLimitKey(ZeroPKID, operation)
	if _checkDAOCoinKeyAndUpdateDerivedKeyEntry(nilCreatorOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// Finally, check (any creator pkid || any operation) key
	nilCreatorAnyOperationKey := MakeDAOCoinOperationLimitKey(ZeroPKID, AnyDAOCoinOperation)
	if _checkDAOCoinKeyAndUpdateDerivedKeyEntry(nilCreatorAnyOperationKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}
	return derivedKeyEntry, RuleErrorDerivedKeyDAOCoinOperationNotAuthorized
}

// _checkDAOCoinLimitOrderLimitKeyAndUpdateDerivedKeyEntry checks if the DAOCoinLimitOrderLimitKey is present
// in the DerivedKeyEntry's TransactionSpendingLimitTracker's DAOCoinLimitOrderLimitMap.
// If the key is present, the operation is allowed and we decrement the number of operations remaining.
// If there are no operations remaining after this one, we delete the key.
// Returns true if the key was found and the derived key entry was updated.
//
// TODO: Right now, the "buy" and "sell" DAO coins that the user is transacting must be
// specified explicitly. There is no way to specify "any" DAO coins in the spending limit
// because ZeroPKID, which we use to specify "any" in other spending limits, corresponds
// to DESO for order book operations. We should fix this down the road.
func _checkDAOCoinLimitOrderLimitKeyAndUpdateDerivedKeyEntry(
	key DAOCoinLimitOrderLimitKey, derivedKeyEntry DerivedKeyEntry) bool {
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinLimitOrderLimitMap == nil {
		return false
	}
	// Check if the key is present in the DAOCoinLimitOrderLimitMap...
	daoCoinLimitOrderLimit, daoCoinLimitOrderLimitExists :=
		derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinLimitOrderLimitMap[key]
	// If the key doesn't exist or the value is <= 0, return false.
	if !daoCoinLimitOrderLimitExists || daoCoinLimitOrderLimit <= 0 {
		return false
	}
	// If this is the last operation allowed for this key, we delete the key from the map.
	if daoCoinLimitOrderLimit == 1 {
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinLimitOrderLimitMap, key)
	} else {
		// Otherwise, we decrement the number of operations remaining for this key
		derivedKeyEntry.TransactionSpendingLimitTracker.DAOCoinLimitOrderLimitMap[key]--
	}
	// Return true because we found the key and decremented the remaining operations
	return true
}

// _checkDAOCoinLimitOrderLimitAndUpdateDerivedKeyEntry checks that the DAO Coin Limit Order
// being performed has been authorized for this derived key.
//
// TODO: Right now, the "buy" and "sell" DAO coins that the user is transacting must be
// specified explicitly. There is no way to specify "any" DAO coins in the spending limit
// because ZeroPKID, which we use to specify "any" in other spending limits, corresponds
// to DESO for order book operations. We should fix this down the road.
func (bav *UtxoView) _checkDAOCoinLimitOrderLimitAndUpdateDerivedKeyEntry(
	derivedKeyEntry DerivedKeyEntry, buyingDAOCoinCreatorPublicKey []byte, sellingDAOCoinCreatorPublicKey []byte) (
	_derivedKeyEntry DerivedKeyEntry, _err error) {
	buyingPKIDEntry := bav.GetPKIDForPublicKey(buyingDAOCoinCreatorPublicKey)
	if buyingPKIDEntry == nil || buyingPKIDEntry.isDeleted {
		return derivedKeyEntry, fmt.Errorf(
			"_checkDAOCoinLimitOrderLimitAndUpdateDerivedKeyEntry: buying pkid is deleted")
	}
	sellingPKIDEntry := bav.GetPKIDForPublicKey(sellingDAOCoinCreatorPublicKey)
	if sellingPKIDEntry == nil || sellingPKIDEntry.isDeleted {
		return derivedKeyEntry, fmt.Errorf(
			"_checkDAOCoinLimitOrderLimitAndUpdateDerivedKeyEntry: selling pkid is deleted")
	}

	// Check (buying DAO Creator PKID || selling DAO Creator PKID) key
	buyingAndSellingKey := MakeDAOCoinLimitOrderLimitKey(*buyingPKIDEntry.PKID, *sellingPKIDEntry.PKID)
	if _checkDAOCoinLimitOrderLimitKeyAndUpdateDerivedKeyEntry(buyingAndSellingKey, derivedKeyEntry) {
		return derivedKeyEntry, nil
	}

	// TODO: How do we want to account for buying ANY creator or selling ANY creator given that we
	// use the ZeroPKID / ZeroPublicKey to represent buying/selling DESO.

	return derivedKeyEntry, errors.Wrapf(RuleErrorDerivedKeyDAOCoinLimitOrderNotAuthorized,
		"_checkDAOCoinLimitOrderLimitAndUpdateDerivedKeyEntr: DAO Coin limit order not authorized: ")
}

func (bav *UtxoView) _checkAssociationLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry,
	associationClass AssociationClass,
	associationType []byte,
	appPublicKey *PublicKey,
	operation AssociationOperation,
) (DerivedKeyEntry, error) {
	// Convert AppPublicKey to AppPKID
	appPKID := bav._associationAppPublicKeyToPKID(appPublicKey)
	// Construct AssociationLimitKey.
	var associationLimitKey AssociationLimitKey
	// Check for applicable spending limit matching:
	//   - Scoped AppScopeType else any AppScopeType
	//   - Scoped AssociationType else any AssociationType
	//   - Scoped OperationType else any OperationType
	for _, spendingLimitScopeType := range []AssociationAppScopeType{AssociationAppScopeTypeScoped, AssociationAppScopeTypeAny} {
		spendingLimitAppPKID := *appPKID
		if spendingLimitScopeType == AssociationAppScopeTypeAny {
			spendingLimitAppPKID = ZeroPKID
		}
		for _, spendingLimitAssociationType := range [][]byte{associationType, []byte("")} {
			for _, spendingLimitOperationType := range []AssociationOperation{operation, AssociationOperationAny} {
				associationLimitKey = MakeAssociationLimitKey(
					associationClass,
					spendingLimitAssociationType,
					spendingLimitAppPKID,
					spendingLimitScopeType,
					spendingLimitOperationType,
				)
				updatedDerivedKeyEntry, err := _checkAssociationLimitAndUpdateDerivedKey(derivedKeyEntry, associationLimitKey)
				if err == nil {
					return updatedDerivedKeyEntry, nil
				}
			}
		}
	}
	// If we get to this point, then no authorized spending limits
	// were found and the association is not authorized.
	return derivedKeyEntry, errors.New("_checkAssociationLimitAndUpdateDerivedKey: association not authorized for derived key")
}

func _checkAssociationLimitAndUpdateDerivedKey(
	derivedKeyEntry DerivedKeyEntry, associationLimitKey AssociationLimitKey,
) (DerivedKeyEntry, error) {
	errMsg := errors.New("_checkAssociationLimitAndUpdateDerivedKey: association not authorized for derived key")
	// If derived key spending limit is missing, return unauthorized.
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.AssociationLimitMap == nil {
		return derivedKeyEntry, errMsg
	}
	// Check if the key is present in the AssociationLimitMap.
	associationLimit, associationLimitExists :=
		derivedKeyEntry.TransactionSpendingLimitTracker.AssociationLimitMap[associationLimitKey]
	// If the key doesn't exist or the value is <= 0, return unauthorized.
	if !associationLimitExists || associationLimit <= 0 {
		return derivedKeyEntry, errMsg
	}
	// If this is the last operation allowed for this key, we delete the key from the map.
	if associationLimit == 1 {
		delete(derivedKeyEntry.TransactionSpendingLimitTracker.AssociationLimitMap, associationLimitKey)
	} else {
		// Otherwise, we decrement the number of operations remaining for this key.
		derivedKeyEntry.TransactionSpendingLimitTracker.AssociationLimitMap[associationLimitKey]--
	}
	// Happy path: we found the key and decremented the remaining operations.
	return derivedKeyEntry, nil
}

// _checkAccessGroupSpendingLimitKeyAndUpdateDerivedKeyEntry checks that the access group spending limit is sufficient
// to cover an accessGroup transaction. If the spending limit is present, we decrement the number of remaining operations
// for the corresponding spending limit entry and return the new derived key entry with the updated spending limit.
func (bav *UtxoView) _checkAccessGroupSpendingLimitAndUpdateDerivedKeyEntry(derivedKeyEntry DerivedKeyEntry,
	accessGroupMetadata *AccessGroupMetadata) (_derivedKeyEntry DerivedKeyEntry, _err error) {

	// Make sure input data is valid.
	if accessGroupMetadata == nil {
		return derivedKeyEntry, fmt.Errorf("_checkAccessGroupSpendingLimitAndUpdateDerivedKeyEntry: " +
			"transaction metadata is empty")
	}
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMap == nil {
		return derivedKeyEntry, fmt.Errorf("_checkAccessGroupSpendingLimitAndUpdateDerivedKeyEntry: " +
			"TransactionSpendingLimitTracker or TransactionSpendingLimitTracker.AccessGroupMap are empty")
	}

	// Validate the access group operation type.
	var operationType AccessGroupOperationType
	switch accessGroupMetadata.AccessGroupOperationType {
	case AccessGroupOperationTypeCreate:
		operationType = AccessGroupOperationTypeCreate
	case AccessGroupOperationTypeUpdate:
		operationType = AccessGroupOperationTypeUpdate
	default:
		return derivedKeyEntry, fmt.Errorf("_checkAccessGroupSpendingLimitAndUpdateDerivedKeyEntry: Unknown access group "+
			"operation type (%v)", accessGroupMetadata.AccessGroupOperationType)
	}

	// Look for the spending limit corresponding to this accessGroupMetadata.
	for _, scopeTypeIter := range []AccessGroupScopeType{AccessGroupScopeTypeScoped, AccessGroupScopeTypeAny} {
		groupKeyName := *NewGroupKeyName(accessGroupMetadata.AccessGroupKeyName)
		if scopeTypeIter == AccessGroupScopeTypeAny {
			groupKeyName = *NewGroupKeyName([]byte{})
		}

		for _, operationTypeIter := range []AccessGroupOperationType{operationType, AccessGroupOperationTypeAny} {
			accessGroupLimitKey := MakeAccessGroupLimitKey(
				*NewPublicKey(accessGroupMetadata.AccessGroupOwnerPublicKey),
				scopeTypeIter,
				groupKeyName,
				operationTypeIter,
			)
			spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMap[accessGroupLimitKey]
			// If spending limit is non-positive, continue.
			if !exists || spendingLimit <= 0 {
				continue
			}

			// Delete the spending limit entry if we've exhausted the spending limit for this key, otherwise decrement it by 1.
			if spendingLimit == 1 {
				delete(derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMap, accessGroupLimitKey)
			} else {
				derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMap[accessGroupLimitKey]--
			}
			return derivedKeyEntry, nil
		}
	}

	// If we get to this point, then no applicable spending limit was found.
	return derivedKeyEntry, errors.Wrapf(
		RuleErrorAccessGroupTransactionSpendingLimitInvalid,
		"_checkAccessGroupSpendingLimitAndUpdateDerivedKeyEntry: No corresponding access group operation spending limit exists",
	)
}

// _checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry checks that the access group members spending limit is sufficient
// to cover an accessGroupMembers transaction. If the spending limit is present, we decrement the number of remaining operations
// for the corresponding spending limit entry and return the new derived key entry with the updated spending limit.
func (bav *UtxoView) _checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry(derivedKeyEntry DerivedKeyEntry,
	accessGroupMembersMetadata *AccessGroupMembersMetadata) (_derivedKeyEntry DerivedKeyEntry, _err error) {

	// Make sure input data is valid.
	if accessGroupMembersMetadata == nil {
		return derivedKeyEntry, fmt.Errorf("_checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry: " +
			"transaction metadata is empty")
	}
	if derivedKeyEntry.TransactionSpendingLimitTracker == nil ||
		derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMemberMap == nil {
		return derivedKeyEntry, fmt.Errorf("_checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry: " +
			"TransactionSpendingLimitTracker or TransactionSpendingLimitTracker.AccessGroupMemberMap are empty")
	}

	var operationType AccessGroupMemberOperationType
	switch accessGroupMembersMetadata.AccessGroupMemberOperationType {
	case AccessGroupMemberOperationTypeAdd:
		operationType = AccessGroupMemberOperationTypeAdd
	case AccessGroupMemberOperationTypeUpdate:
		operationType = AccessGroupMemberOperationTypeUpdate
	case AccessGroupMemberOperationTypeRemove:
		operationType = AccessGroupMemberOperationTypeRemove
	default:
		return derivedKeyEntry, fmt.Errorf("_checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry: "+
			"operation type (%v)", accessGroupMembersMetadata.AccessGroupMemberOperationType)
	}

	// Look for the spending limit corresponding to this accessGroupMembersMetadata.
	for _, scopeTypeIter := range []AccessGroupScopeType{AccessGroupScopeTypeScoped, AccessGroupScopeTypeAny} {
		groupKeyName := *NewGroupKeyName(accessGroupMembersMetadata.AccessGroupKeyName)
		if scopeTypeIter == AccessGroupScopeTypeAny {
			groupKeyName = *NewGroupKeyName([]byte{})
		}

		for _, operationTypeIter := range []AccessGroupMemberOperationType{operationType, AccessGroupMemberOperationTypeAny} {
			accessGroupMembersLimitKey := MakeAccessGroupMemberLimitKey(
				*NewPublicKey(accessGroupMembersMetadata.AccessGroupOwnerPublicKey),
				scopeTypeIter,
				groupKeyName,
				operationTypeIter,
			)
			spendingLimit, exists := derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMemberMap[accessGroupMembersLimitKey]
			// If spending limit is non-positive, continue.
			if !exists || spendingLimit <= 0 {
				continue
			}

			// Delete the spending limit entry if we've exhausted the spending limit for this key, otherwise decrement it by 1.
			if spendingLimit == 1 {
				delete(derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMemberMap, accessGroupMembersLimitKey)
			} else {
				derivedKeyEntry.TransactionSpendingLimitTracker.AccessGroupMemberMap[accessGroupMembersLimitKey]--
			}
			return derivedKeyEntry, nil
		}
	}

	// If we get to this point, then no applicable spending limit was found.
	return derivedKeyEntry, errors.Wrapf(
		RuleErrorAccessGroupMemberSpendingLimitInvalid,
		"_checkAccessGroupMembersSpendingLimitAndUpdateDerivedKeyEntry: No corresponding access group operation spending limit exists",
	)
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
	_, updaterIsParamUpdater := GetParamUpdaterPublicKeys(blockHeight, bav.Params)[MakePkMapKey(txn.PublicKey)]
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

	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight &&
		len(extraData[MaxNonceExpirationBlockHeightOffsetKey]) > 0 {

		newMaxNonceExpirationBlockHeightOffset, maxNonceExpirationBlockHeightOffsetBytesRead := Uvarint(extraData[MaxNonceExpirationBlockHeightOffsetKey])
		if maxNonceExpirationBlockHeightOffsetBytesRead <= 0 {
			return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode MaxNonceExpirationBlockHeightOffset as uint64")
		}
		newGlobalParamsEntry.MaxNonceExpirationBlockHeightOffset = newMaxNonceExpirationBlockHeightOffset
	}

	if blockHeight >= bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight {
		var bytesRead int
		if len(extraData[StakeLockupEpochDurationKey]) > 0 {
			newGlobalParamsEntry.StakeLockupEpochDuration, bytesRead = Uvarint(extraData[StakeLockupEpochDurationKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode StakeLockupEpochDuration as uint64")
			}
		}
		if len(extraData[ValidatorJailEpochDurationKey]) > 0 {
			newGlobalParamsEntry.ValidatorJailEpochDuration, bytesRead = Uvarint(extraData[ValidatorJailEpochDurationKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode ValidatorJailEpochDuration as uint64")
			}
		}
		if len(extraData[LeaderScheduleMaxNumValidatorsKey]) > 0 {
			newGlobalParamsEntry.LeaderScheduleMaxNumValidators, bytesRead = Uvarint(extraData[LeaderScheduleMaxNumValidatorsKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode LeaderScheduleMaxNumValidators as uint64")
			}
		}
		if len(extraData[ValidatorSetMaxNumValidatorsKey]) > 0 {
			newGlobalParamsEntry.ValidatorSetMaxNumValidators, bytesRead = Uvarint(extraData[ValidatorSetMaxNumValidatorsKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode ValidatorSetMaxNumValidators as uint64")
			}
		}

		// Cross-validate the new LeaderScheduleMaxNumValidators and ValidatorSetMaxNumValidators values. The size of the
		// leader schedule must be less than or equal to the size of the validator set.
		if newGlobalParamsEntry.ValidatorSetMaxNumValidators < newGlobalParamsEntry.LeaderScheduleMaxNumValidators {
			return 0, 0, nil, RuleErrorLeaderScheduleExceedsValidatorSetMaxNumValidators
		}

		if len(extraData[StakingRewardsMaxNumStakesKey]) > 0 {
			newGlobalParamsEntry.StakingRewardsMaxNumStakes, bytesRead = Uvarint(extraData[StakingRewardsMaxNumStakesKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode StakingRewardsMaxNumStakes as uint64")
			}
		}
		if len(extraData[StakingRewardsAPYBasisPointsKey]) > 0 {
			newGlobalParamsEntry.StakingRewardsAPYBasisPoints, bytesRead = Uvarint(extraData[StakingRewardsAPYBasisPointsKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode StakingRewardsAPYBasisPoints as uint64")
			}
		}
		if len(extraData[EpochDurationNumBlocksKey]) > 0 {
			newGlobalParamsEntry.EpochDurationNumBlocks, bytesRead = Uvarint(extraData[EpochDurationNumBlocksKey])
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf("_connectUpdateGlobalParams: unable to decode EpochDurationNumBlocks as uint64")
			}
		}
		if len(extraData[JailInactiveValidatorGracePeriodEpochsKey]) > 0 {
			newGlobalParamsEntry.JailInactiveValidatorGracePeriodEpochs, bytesRead = Uvarint(
				extraData[JailInactiveValidatorGracePeriodEpochsKey],
			)
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: unable to decode JailInactiveValidatorGracePeriodEpochs as uint64",
				)
			}
		}
		if len(extraData[MaximumVestedIntersectionsPerLockupTransactionKey]) > 0 {
			maximumVestedIntersectionsPerLockupTransaction, bytesRead := Varint(
				extraData[MaximumVestedIntersectionsPerLockupTransactionKey],
			)
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: " +
						"unable to decode MaximumVestedIntersectionsPerLockupTransaction as uint64")
			}
			newGlobalParamsEntry.MaximumVestedIntersectionsPerLockupTransaction =
				int(maximumVestedIntersectionsPerLockupTransaction)
		}
		if len(extraData[FeeBucketGrowthRateBasisPointsKey]) > 0 {
			val, bytesRead := Uvarint(
				extraData[FeeBucketGrowthRateBasisPointsKey],
			)
			if val > MaxBasisPoints {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: FeeBucketGrowthRateBasisPoints must be <= %d",
					MaxBasisPoints,
				)
			}
			newGlobalParamsEntry.FeeBucketGrowthRateBasisPoints = val
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: unable to decode FeeBucketGrowthRateBasisPoints as uint64",
				)
			}
		}
		if len(extraData[FailingTransactionBMFMultiplierBasisPointsKey]) > 0 {
			val, bytesRead := Uvarint(
				extraData[FailingTransactionBMFMultiplierBasisPointsKey],
			)
			if val > MaxBasisPoints {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: FailingTransactionBMFMultiplierBasisPoints must be <= %d",
					MaxBasisPoints,
				)
			}
			newGlobalParamsEntry.FailingTransactionBMFMultiplierBasisPoints = val

			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: unable to decode FailingTransactionBMFMultiplierBasisPoints as uint64",
				)
			}
		}
		if len(extraData[BlockTimestampDriftNanoSecsKey]) > 0 {
			val, bytesRead := Varint(
				extraData[BlockTimestampDriftNanoSecsKey],
			)
			if bytesRead <= 0 {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: unable to decode BlockTimestampDriftNanoSecs as int64",
				)
			}
			if val < 0 {
				return 0, 0, nil, fmt.Errorf(
					"_connectUpdateGlobalParams: BlockTimestampDriftNanoSecs must be >= 0",
				)
			}
			newGlobalParamsEntry.BlockTimestampDriftNanoSecs = val
		}
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
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateGlobalParams: ")
	}

	// Output must be non-zero
	if totalOutput == 0 && blockHeight < bav.Params.ForkHeights.BalanceModelBlockHeight {
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

func (bav *UtxoView) ConnectTransaction(
	txn *MsgDeSoTxn, txHash *BlockHash,
	blockHeight uint32, blockTimestampNanoSecs int64, verifySignatures bool,
	ignoreUtxos bool) (_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64, _fees uint64, _err error) {
	return bav._connectTransaction(txn, txHash, blockHeight, blockTimestampNanoSecs, verifySignatures, ignoreUtxos)

}

func (bav *UtxoView) _connectTransaction(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32,
	blockTimestampNanoSecs int64, verifySignatures bool,
	ignoreUtxos bool) (_utxoOps []*UtxoOperation, _totalInput uint64, _totalOutput uint64, _fees uint64, _err error) {
	// Do a quick sanity check before trying to connect.
	if err := CheckTransactionSanity(txn, blockHeight, bav.Params); err != nil {
		return nil, 0, 0, 0, errors.Wrapf(err, "_connectTransaction: ")
	}

	// Don't allow transactions that take up more than half of the block.
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, 0, 0, 0, errors.Wrapf(
			err, "_connectTransaction: Problem serializing transaction: ")
	}
	txnSizeBytes := uint64(len(txnBytes))
	if txnSizeBytes > bav.Params.MaxBlockSizeBytes/2 {
		return nil, 0, 0, 0, RuleErrorTxnTooBig
	}

	// Take snapshot of balance
	balanceSnapshot := make(map[PublicKey]uint64)
	var creatorCoinSnapshot *CoinEntry
	nftCreatorCoinRoyaltyEntriesSnapshot := make(map[PKID]*CoinEntry)
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight {
		for publicKey, balance := range bav.PublicKeyToDeSoBalanceNanos {
			balanceSnapshot[publicKey] = balance
		}
		// Special case: take snapshot of the creator coin entry.
		if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			// Get the creator coin entry.
			creatorCoinTxnMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
			creatorProfile := bav.GetProfileEntryForPublicKey(creatorCoinTxnMeta.ProfilePublicKey)
			if creatorProfile == nil || creatorProfile.IsDeleted() {
				return nil, 0, 0, 0, fmt.Errorf("_connectTransaction: Profile not found for "+
					"public key: %v", PkToString(creatorCoinTxnMeta.ProfilePublicKey, bav.Params))
			}
			creatorCoinSnapshot = creatorProfile.CreatorCoinEntry.Copy()
		}
		// When an NFT is sold, we may need to account for royalties that end up getting
		// generated and paid to a user's creator coin directly.
		if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid || txn.TxnMeta.GetTxnType() == TxnTypeNFTBid {
			// We don't really care if it's an NFT buy now bid or not. We just want to
			// capture the royalties that occur to account for ALL DESO.
			var nftPostHash *BlockHash
			if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
				nftPostHash = txn.TxnMeta.(*AcceptNFTBidMetadata).NFTPostHash
			} else {
				nftPostHash = txn.TxnMeta.(*NFTBidMetadata).NFTPostHash
			}
			postEntry := bav.GetPostEntryForPostHash(nftPostHash)
			if postEntry == nil || postEntry.IsDeleted() {
				return nil, 0, 0, 0, errors.Wrapf(RuleErrorNFTBidOnNonExistentPost, "_connectTransaction: PostEntry not found for "+
					"post hash: %v", nftPostHash.String())
			}
			nftCreatorProfileEntry := bav.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
			if nftCreatorProfileEntry == nil || nftCreatorProfileEntry.IsDeleted() {
				return nil, 0, 0, 0, fmt.Errorf("_connectTransaction: Profile not found for "+
					"public key: %v", PkToString(postEntry.PosterPublicKey, bav.Params))
			}
			pkidEntry := bav.GetPKIDForPublicKey(postEntry.PosterPublicKey)
			if pkidEntry == nil || pkidEntry.isDeleted {
				return nil, 0, 0, 0, fmt.Errorf("_connectTransaction: PKID not found for "+
					"public key: %v", PkToString(postEntry.PosterPublicKey, bav.Params))
			}
			nftCreatorCoinRoyaltyEntriesSnapshot[*(pkidEntry.PKID)] = nftCreatorProfileEntry.CreatorCoinEntry.Copy()
			for pkid := range postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints {
				profileEntry := bav.GetProfileEntryForPKID(&pkid)
				if profileEntry == nil || profileEntry.IsDeleted() {
					return nil, 0, 0, 0, fmt.Errorf("_connectTransaction: Profile not found for "+
						"pkid: %v", PkToString(pkid.ToBytes(), bav.Params))
				}
				nftCreatorCoinRoyaltyEntriesSnapshot[pkid] = profileEntry.CreatorCoinEntry.Copy()
			}
		}
	}

	var totalInput, totalOutput uint64
	var utxoOpsForTxn []*UtxoOperation
	switch txn.TxnMeta.GetTxnType() {
	case TxnTypeBlockReward, TxnTypeBasicTransfer:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBasicTransfer(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeBitcoinExchange:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBitcoinExchange(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypePrivateMessage:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectPrivateMessage(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeMessagingGroup:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectMessagingGroup(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeSubmitPost:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectSubmitPost(
				txn, txHash, blockHeight, verifySignatures, ignoreUtxos)

	case TxnTypeUpdateProfile:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateProfile(
				txn, txHash, blockHeight, verifySignatures, ignoreUtxos)

	case TxnTypeUpdateBitcoinUSDExchangeRate:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateBitcoinUSDExchangeRate(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeUpdateGlobalParams:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateGlobalParams(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeFollow:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectFollow(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeLike:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectLike(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeCreatorCoin:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCreatorCoin(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeCreatorCoinTransfer:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCreatorCoinTransfer(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeDAOCoin:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectDAOCoin(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeDAOCoinTransfer:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectDAOCoinTransfer(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeDAOCoinLimitOrder:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectDAOCoinLimitOrder(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeSwapIdentity:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectSwapIdentity(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeCreateNFT:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectCreateNFT(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeUpdateNFT:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectUpdateNFT(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeAcceptNFTBid:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAcceptNFTBid(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeNFTBid:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectNFTBid(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeNFTTransfer:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectNFTTransfer(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeAcceptNFTTransfer:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAcceptNFTTransfer(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeBurnNFT:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectBurnNFT(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeAuthorizeDerivedKey:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAuthorizeDerivedKey(
				txn, txHash, blockHeight, verifySignatures)
	case TxnTypeCreateUserAssociation:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectCreateUserAssociation(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeDeleteUserAssociation:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectDeleteUserAssociation(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeCreatePostAssociation:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectCreatePostAssociation(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeDeletePostAssociation:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectDeletePostAssociation(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeAccessGroup:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAccessGroup(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeAccessGroupMembers:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectAccessGroupMembers(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeNewMessage:
		totalInput, totalOutput, utxoOpsForTxn, err =
			bav._connectNewMessage(
				txn, txHash, blockHeight, verifySignatures)

	case TxnTypeRegisterAsValidator:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectRegisterAsValidator(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeUnregisterAsValidator:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectUnregisterAsValidator(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeStake:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectStake(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeUnstake:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectUnstake(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeUnlockStake:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectUnlockStake(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeUnjailValidator:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectUnjailValidator(txn, txHash, blockHeight, verifySignatures)

	case TxnTypeCoinLockup:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectCoinLockup(txn, txHash, blockHeight, blockTimestampNanoSecs, verifySignatures)
	case TxnTypeUpdateCoinLockupParams:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectUpdateCoinLockupParams(txn, txHash, blockHeight, verifySignatures)
	case TxnTypeCoinLockupTransfer:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectCoinLockupTransfer(txn, txHash, blockHeight, verifySignatures)
	case TxnTypeCoinUnlock:
		totalInput, totalOutput, utxoOpsForTxn, err = bav._connectCoinUnlock(txn, txHash, blockHeight, blockTimestampNanoSecs, verifySignatures)

	default:
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
		// After the balance model block height, fees are specified in the transaction and
		// cannot be assumed to be equal to total input - total output.
		if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight {
			fees = txn.TxnFeeNanos
		}
	}
	// Validate that totalInput - totalOutput is equal to the fee specified in the transaction metadata.
	if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoinLimitOrder {
		if fees != txn.TxnMeta.(*DAOCoinLimitOrderMetadata).FeeNanos {
			return nil, 0, 0, 0, RuleErrorDAOCoinLimitOrderTotalInputMinusTotalOutputNotEqualToFee
		}
	}

	// BitcoinExchange transactions have their own special fee that is computed as a function of how much
	// DeSo is being minted. They do not need to abide by the global minimum fee check, since if they had
	// enough fees to get mined into the Bitcoin blockchain itself then they're almost certainly not spam.
	// If the transaction size was set to 0, skip validating the fee is above the minimum.
	// If the current minimum network fee per kb is set to 0, that indicates we should not assess a minimum fee.
	// Similarly, BlockReward transactions do not require a fee.
	isFeeExempt := txn.TxnMeta.GetTxnType() == TxnTypeBitcoinExchange || txn.TxnMeta.GetTxnType() == TxnTypeBlockReward
	if !isFeeExempt && txnSizeBytes != 0 && bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB != 0 {
		// Make sure there isn't overflow in the fee.
		if fees != ((fees * 1000) / 1000) {
			return nil, 0, 0, 0, RuleErrorOverflowDetectedInFeeRateCalculation
		}
		// If the fee is less than the minimum network fee per KB, return an error.
		if (fees*1000)/uint64(txnSizeBytes) < bav.GlobalParamsEntry.MinimumNetworkFeeNanosPerKB {
			return nil, 0, 0, 0, RuleErrorTxnFeeBelowNetworkMinimum
		}
	}

	// Validate that we aren't printing any DESO
	if txn.TxnMeta.GetTxnType() != TxnTypeBlockReward &&
		txn.TxnMeta.GetTxnType() != TxnTypeBitcoinExchange &&
		blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight {
		balanceDelta, _, err := bav._compareBalancesToSnapshot(balanceSnapshot)
		if err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err, "ConnectTransaction: error comparing current balances to snapshot")
		}
		desoLockedDelta := big.NewInt(0)
		if txn.TxnMeta.GetTxnType() == TxnTypeCreatorCoin {
			ccMeta := txn.TxnMeta.(*CreatorCoinMetadataa)
			creatorProfile := bav.GetProfileEntryForPublicKey(ccMeta.ProfilePublicKey)
			if creatorProfile == nil || creatorProfile.IsDeleted() {
				return nil, 0, 0, 0, fmt.Errorf("ConnectTransaction: Profile for CreatorCoin being sold does not exist")
			}
			desoLockedDelta = big.NewInt(0).Sub(big.NewInt(0).SetUint64(creatorProfile.CreatorCoinEntry.DeSoLockedNanos),
				big.NewInt(0).SetUint64(creatorCoinSnapshot.DeSoLockedNanos))
		}
		if txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid ||
			txn.TxnMeta.GetTxnType() == TxnTypeNFTBid {

			for pkid, coinEntry := range nftCreatorCoinRoyaltyEntriesSnapshot {
				creatorProfile := bav.GetProfileEntryForPKID(&pkid)
				if creatorProfile == nil || creatorProfile.IsDeleted() {
					return nil, 0, 0, 0, fmt.Errorf("ConnectTransaction: Profile for NFT being sold does not exist")
				}
				desoLockedDelta = desoLockedDelta.Sub(desoLockedDelta,
					big.NewInt(0).Sub(
						big.NewInt(0).SetUint64(creatorProfile.CreatorCoinEntry.DeSoLockedNanos),
						big.NewInt(0).SetUint64(coinEntry.DeSoLockedNanos)),
				)
			}
		}
		if txn.TxnMeta.GetTxnType() == TxnTypeUnlockStake {
			if len(utxoOpsForTxn) == 0 {
				return nil, 0, 0, 0, errors.New(
					"ConnectTransaction: TxnTypeUnlockStake must return UtxoOpsForTxn",
				)
			}
			utxoOp := utxoOpsForTxn[len(utxoOpsForTxn)-1]
			if utxoOp == nil || utxoOp.Type != OperationTypeUnlockStake {
				return nil, 0, 0, 0, errors.New(
					"ConnectTransaction: TxnTypeUnlockStake must correspond to OperationTypeUnlockStake",
				)
			}
			totalLockedAmountNanos := uint256.NewInt()
			for _, prevLockedStakeEntry := range utxoOp.PrevLockedStakeEntries {
				totalLockedAmountNanos, err = SafeUint256().Add(
					totalLockedAmountNanos, prevLockedStakeEntry.LockedAmountNanos,
				)
				if err != nil {
					return nil, 0, 0, 0, errors.Wrapf(err, "ConnectTransaction: error computing TotalLockedAmountNanos: ")
				}
			}
			desoLockedDelta = big.NewInt(0).Neg(totalLockedAmountNanos.ToBig())
		}
		if txn.TxnMeta.GetTxnType() == TxnTypeCoinUnlock {
			if len(utxoOpsForTxn) == 0 {
				return nil, 0, 0, 0, errors.New(
					"ConnectTransaction: TxnTypeCoinUnlock must return UtxoOpsForTxn",
				)
			}
			coinUnlockMeta := txn.TxnMeta.(*CoinUnlockMetadata)

			// We only count DESO added if coin unlock was a locked DESO unlock.
			if coinUnlockMeta.ProfilePublicKey.IsZeroPublicKey() {
				utxoOp := utxoOpsForTxn[len(utxoOpsForTxn)-1]
				if utxoOp == nil || utxoOp.Type != OperationTypeCoinUnlock {
					return nil, 0, 0, 0, errors.New(
						"ConnectTransaction: TxnTypeCoinUnlock must correspond to OperationTypeCoinUnlock",
					)
				}
				totalLockedDESOAmountNanos := uint256.NewInt()
				for _, prevLockedBalanceEntry := range utxoOp.PrevLockedBalanceEntries {
					totalLockedDESOAmountNanos, err = SafeUint256().Add(
						totalLockedDESOAmountNanos, &prevLockedBalanceEntry.BalanceBaseUnits)
					if err != nil {
						return nil, 0, 0, 0,
							errors.Wrapf(err, "ConnectTransaction: error computing TotalLockedCoinsAmountNanos: ")
					}
					if !totalLockedDESOAmountNanos.IsUint64() {
						return nil, 0, 0, 0,
							errors.Errorf("ConnectTransaction: totalLockedDESOAmountNanos overflows uint64")
					}
				}
				desoLockedDelta = big.NewInt(0).Neg(totalLockedDESOAmountNanos.ToBig())
			}
		}
		if big.NewInt(0).Add(balanceDelta, desoLockedDelta).Sign() > 0 {
			return nil, 0, 0, 0, RuleErrorBalanceChangeGreaterThanZero
		}
	}

	// For all transactions other than block rewards, validate the nonce.
	if blockHeight >= bav.Params.ForkHeights.BalanceModelBlockHeight &&
		txn.TxnMeta.GetTxnType() != TxnTypeBlockReward {

		if err := bav.ValidateTransactionNonce(txn, uint64(blockHeight)); err != nil {
			return nil, 0, 0, 0, errors.Wrapf(err,
				"ConnectTransaction: error validating transaction nonce")
		}
		pkidEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
		if pkidEntry == nil || pkidEntry.isDeleted {
			return nil, 0, 0, 0, fmt.Errorf(
				"ConnectTransaction: PKID for public key %s does not exist",
				PkToString(txn.PublicKey, bav.Params))
		}

		bav.SetTransactorNonceEntry(&TransactorNonceEntry{
			Nonce:          txn.TxnNonce,
			TransactorPKID: pkidEntry.PKID,
		})
	}

	return utxoOpsForTxn, totalInput, totalOutput, fees, nil
}

func (bav *UtxoView) ValidateTransactionNonce(txn *MsgDeSoTxn, blockHeight uint64) error {
	if txn == nil || txn.TxnNonce == nil {
		return fmt.Errorf("ValidateTransactionNonce: Nonce or txn is nil for public key %v",
			PkToStringBoth(txn.PublicKey))
	}

	if blockHeight > txn.TxnNonce.ExpirationBlockHeight {
		return errors.Wrapf(RuleErrorNonceExpired,
			"ValidateTransactionNonce: Nonce %s has expired for public key %v",
			txn.TxnNonce.String(), PkToStringBoth(txn.PublicKey))
	}
	pkidEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if pkidEntry == nil || pkidEntry.isDeleted {
		return fmt.Errorf(
			"ValidateTransactionNonce: PKID for public key %s does not exist",
			PkToString(txn.PublicKey, bav.Params))
	}

	nonce, err := bav.GetTransactorNonceEntry(txn.TxnNonce, pkidEntry.PKID)
	if err != nil {
		return errors.Wrapf(err,
			"ValidateTransactionNonce: Problem getting transaction nonce entry for nonce %s and PKID %v",
			txn.TxnNonce.String(), pkidEntry.PKID)
	}
	if nonce != nil && !nonce.isDeleted {
		return errors.Wrapf(RuleErrorReusedNonce,
			"ValidateTransactionNonce: Nonce %s has already been used for PKID %v",
			txn.TxnNonce.String(), pkidEntry.PKID)
	}
	return nil
}

// _connectFailingTransaction is used to process the fee and burn associated with the user submitting a failing transaction.
// A failing transaction is a txn that passes formatting validation, yet fails connecting to the UtxoView. This can happen for a
// number of reasons, such as insufficient DESO balance, wrong public key, etc. With Revolution's Fee-Time block ordering, these
// failing transactions are included in the blocks and their fees are burned. In addition, a major part of the effective
// fees of this transaction is burned with BMF. This makes spam attacks economically disadvantageous. Attacker's funds
// are burned, to the benefit of everyone else on the network. BMF algorithm also computes a utility fee, which is
// distributed to the block producer.
func (bav *UtxoView) _connectFailingTransaction(txn *MsgDeSoTxn, blockHeight uint32, verifySignatures bool) (
	_utxoOps []*UtxoOperation, _burnFee uint64, _utilityFee uint64, _err error) {

	// Failing transactions are only allowed after ProofOfStake2ConsensusCutoverBlockHeight.
	if blockHeight < bav.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight {
		return nil, 0, 0, fmt.Errorf("_connectFailingTransaction: Failing transactions " +
			"not allowed before ProofOfStake2ConsensusCutoverBlockHeight")
	}

	// Sanity check the transaction to make sure it is properly formatted.
	if err := CheckTransactionSanity(txn, blockHeight, bav.Params); err != nil {
		return nil, 0, 0, errors.Wrapf(err, "_connectFailingTransaction: "+
			"Problem checking txn sanity")
	}

	if err := ValidateDeSoTxnSanityBalanceModel(txn, uint64(blockHeight), bav.Params, bav.GlobalParamsEntry); err != nil {
		return nil, 0, 0, errors.Wrapf(err, "_connectFailingTransaction: "+
			"Problem checking txn sanity under balance model")
	}

	if err := bav.ValidateTransactionNonce(txn, uint64(blockHeight)); err != nil {
		return nil, 0, 0, errors.Wrapf(err, "_connectFailingTransaction: "+
			"Problem validating transaction nonce")
	}

	// Get the FailingTransactionBMFMultiplierBasisPoints from the global params entry. We then compute the effective fee
	// as: effectiveFee = txn.TxnFeeNanos * FailingTransactionBMFMultiplierBasisPoints / 10000
	gp := bav.GetCurrentGlobalParamsEntry()

	failingTransactionRate := uint256.NewInt().SetUint64(gp.FailingTransactionBMFMultiplierBasisPoints)
	failingTransactionFee := uint256.NewInt().SetUint64(txn.TxnFeeNanos)
	basisPointsAsUint256 := uint256.NewInt().SetUint64(MaxBasisPoints)

	effectiveFeeU256 := uint256.NewInt()
	if effectiveFeeU256.MulOverflow(failingTransactionRate, failingTransactionFee) {
		return nil, 0, 0, fmt.Errorf("_connectFailingTransaction: Problem computing effective fee")
	}
	effectiveFeeU256.Div(effectiveFeeU256, basisPointsAsUint256)

	// We should never overflow on the effective fee, since FailingTransactionBMFMultiplierBasisPoints is <= 10000.
	// But if for some magical reason we do, we set the effective fee to the max uint64. We don't error, and
	// instead let _spendBalance handle the overflow.
	if !effectiveFeeU256.IsUint64() {
		effectiveFeeU256.SetUint64(math.MaxUint64)
	}
	effectiveFee := effectiveFeeU256.Uint64()

	// Serialize the transaction to bytes so we can compute its size.
	txnBytes, err := txn.ToBytes(false)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "_connectFailingTransaction: Problem serializing transaction: ")
	}
	txnSizeBytes := uint64(len(txnBytes))

	// If the effective fee rate per KB is less than the minimum network fee rate per KB, we set it to the minimum
	// network fee rate per KB. We multiply by 1000 and divide by the txn bytes to convert the txn's total effective
	// fee to a fee rate per KB.
	//
	// The effectiveFee * 1000 computation is guaranteed to not overflow because an overflow check is already
	// performed in ValidateDeSoTxnSanityBalanceModel above.
	effectiveFeeRateNanosPerKB := (effectiveFee * 1000) / txnSizeBytes
	if effectiveFeeRateNanosPerKB < gp.MinimumNetworkFeeNanosPerKB {
		// The minimum effective fee for the txn is the txn size * the minimum network fee rate per KB.
		effectiveFee = (gp.MinimumNetworkFeeNanosPerKB * txnSizeBytes) / 1000
	}

	burnFee, utilityFee := computeBMF(effectiveFee)

	var utxoOps []*UtxoOperation
	// When spending balances, we need to check for immature block rewards. Since we don't have
	// the block rewards yet for the current block, we subtract one from the current block height
	// when spending balances.
	feeUtxoOp, err := bav._spendBalance(effectiveFee, txn.PublicKey, blockHeight-1)
	if err != nil {
		return nil, 0, 0, errors.Wrapf(err, "_connectFailingTransaction: Problem "+
			"spending balance")
	}
	utxoOps = append(utxoOps, feeUtxoOp)

	// If verifySignatures is passed, we check transaction signature.
	if verifySignatures {
		if err := bav._verifyTxnSignature(txn, blockHeight); err != nil {
			return nil, 0, 0, errors.Wrapf(err, "_connectFailingTransaction: Problem "+
				"verifying signature")
		}
	}

	return utxoOps, burnFee, utilityFee, nil
}

// computeBMF computes the burn fee and the utility fee for a given fee. The acronym stands for Burn Maximizing Fee, which
// entails that the burn function is designed to maximize the amount of DESO burned, while providing the minimal viable
// utility fee to the block producer. This is so that block producers have no advantage over other network participants
// in accruing DESO. The utility fee that block producers get from transaction fees is just enough so that it's economically
// advantageous to include as many transactions as possible in blocks. Reliably doing so for an extended period of time
// could accumulate to some DESO from transaction fees.
// The utility fee is computed by taking a binary logarithm of the fee, and the remainder is burned. BMF(fee) computes:
//
//	burnFee := fee - log_2(fee), utilityFee := log_2(fee).
func computeBMF(fee uint64) (_burnFee uint64, _utilityFee uint64) {
	// If no fee, burn and utility fee are both 0.
	if fee == 0 {
		return 0, 0
	}
	// Compute the utility fee as log_2(fee). We can find it by taking the bit length of fee.
	// Alternatively: uint64(bits.Len64(fee))
	utilityFee, _ := BigFloatLog2(NewFloat().SetUint64(fee)).Uint64()

	// This should never happen but just in case make sure utilityFee is not greater than fee.
	if utilityFee > fee {
		utilityFee = fee
	}
	// Compute the burn as fee - log_2(fee).
	burnFee := fee - utilityFee
	return burnFee, utilityFee
}

func (bav *UtxoView) _compareBalancesToSnapshot(balanceSnapshot map[PublicKey]uint64) (
	*big.Int, map[PublicKey]*big.Int, error) {
	runningTotal := big.NewInt(0)
	balanceDeltasMap := make(map[PublicKey]*big.Int)
	for publicKey, balance := range bav.PublicKeyToDeSoBalanceNanos {
		snapshotBalance, exists := balanceSnapshot[publicKey]
		if !exists {
			// Get it from the DB
			dbBalance, err := bav.GetDbAdapter().GetDeSoBalanceForPublicKey(publicKey.ToBytes())
			if err != nil {
				return nil, nil, err
			}
			snapshotBalance = dbBalance
			balanceSnapshot[publicKey] = snapshotBalance
		}
		// New - Old
		delta := big.NewInt(0).Sub(big.NewInt(0).SetUint64(balance), big.NewInt(0).SetUint64(snapshotBalance))
		balanceDeltasMap[publicKey] = delta
		runningTotal = big.NewInt(0).Add(runningTotal, delta)
	}
	return runningTotal, balanceDeltasMap, nil
}

func (bav *UtxoView) ConnectBlock(
	desoBlock *MsgDeSoBlock, txHashes []*BlockHash, verifySignatures bool, eventManager *EventManager, blockHeight uint64) (
	[][]*UtxoOperation, error) {

	glog.V(1).Infof("ConnectBlock: Connecting block %v", desoBlock)

	// Check that the block being connected references the current tip. ConnectBlock
	// can only add a block to the current tip. We do this to keep the API simple.
	if *desoBlock.Header.PrevBlockHash != *bav.TipHash {
		return nil, fmt.Errorf("ConnectBlock: Parent hash of block being connected does not match tip")
	}

	blockHeader := desoBlock.Header
	var blockRewardOutputPublicKey *btcec.PublicKey
	// If the block height is greater than or equal to the block reward patch height,
	// we will verify that there is only one block reward output and we'll parse
	// that public key
	if blockHeight >= uint64(bav.Params.ForkHeights.BlockRewardPatchBlockHeight) {
		// Make sure the block has transactions
		if len(desoBlock.Txns) == 0 {
			return nil, errors.Wrap(RuleErrorNoTxns, "ConnectBlock: Block has no transactions")
		}
		// Make sure the first transaction is a block reward.
		if desoBlock.Txns[0].TxnMeta.GetTxnType() != TxnTypeBlockReward {
			return nil, errors.Wrap(RuleErrorFirstTxnMustBeBlockReward, "ConnectBlock: First transaction in block is not a block reward")
		}
		// Ensure that the block reward transaction has exactly one output.
		if len(desoBlock.Txns[0].TxOutputs) != 1 {
			return nil, errors.Wrap(RuleErrorBlockRewardTxnMustHaveOneOutput, "ConnectBlock: Block reward transaction must have exactly one output")
		}
		var err error
		blockRewardOutputPublicKey, err =
			btcec.ParsePubKey(desoBlock.Txns[0].TxOutputs[0].PublicKey, btcec.S256())
		if err != nil {
			return nil, fmt.Errorf("ConnectBlock: Problem parsing block reward public key: %v", err)
		}
	}

	// Loop through all the transactions and validate them using the view. Also
	// keep track of the total fees throughout.
	var totalFees uint64
	utxoOps := [][]*UtxoOperation{}
	var maxUtilityFee uint64
	for txIndex, txn := range desoBlock.Txns {
		txHash := txHashes[txIndex]

		// PoS introduced a concept of a failing transaction, or transactions that fail UtxoView's ConnectTransaction.
		// In PoS, these failing transactions are included in the block and their fees are burned.

		// To determine if we're dealing with a connecting or failing transaction, we first check if we're on a PoS block
		// height. Otherwise, the transaction is expected to connect.
		hasPoWBlockHeight := bav.Params.IsPoWBlockHeight(blockHeight)
		// Also, the first transaction in the block, the block reward transaction, should always be a connecting transaction.
		isBlockRewardTxn := (txIndex == 0) && (txn.TxnMeta.GetTxnType() == TxnTypeBlockReward)
		// Finally, if the transaction is not the first in the block, we check the TxnConnectStatusByIndex to see if
		// it's marked by the block producer as a connecting transaction. PoS blocks should reflect this in TxnConnectStatusByIndex.
		hasConnectingPoSTxnStatus := false
		if bav.Params.IsPoSBlockHeight(blockHeight) && (txIndex > 0) && (desoBlock.TxnConnectStatusByIndex != nil) {
			// Note that TxnConnectStatusByIndex doesn't include the first block reward transaction.
			hasConnectingPoSTxnStatus = desoBlock.TxnConnectStatusByIndex.Get(txIndex - 1)
		}
		// Now, we can determine if the transaction is expected to connect.
		txnConnects := hasPoWBlockHeight || isBlockRewardTxn || hasConnectingPoSTxnStatus

		var utilityFee uint64
		var utxoOpsForTxn []*UtxoOperation
		var err error
		var currentFees uint64
		if txnConnects {
			// ConnectTransaction validates all of the transactions in the block and
			// is responsible for verifying signatures.
			//
			// TODO: We currently don't check that the min transaction fee is satisfied when
			// connecting blocks. We skip this check because computing the transaction's size
			// would slow down block processing significantly. We should figure out a way to
			// enforce this check in the future, but for now the only attack vector is one in
			// which a miner is trying to spam the network, which should generally never happen.
			utxoOpsForTxn, _, _, currentFees, err = bav.ConnectTransaction(
				txn, txHash, uint32(blockHeader.Height), blockHeader.TstampNanoSecs, verifySignatures, false)
			if err != nil {
				return nil, errors.Wrapf(err, "ConnectBlock: error connecting txn #%d", txIndex)
			}
			_, utilityFee = computeBMF(currentFees)
		} else {
			// If the transaction is not supposed to connect, we need to verify that it won't connect.
			// We need to construct a copy of the view to verify that the transaction won't connect
			// without side effects.
			var utxoViewCopy *UtxoView
			utxoViewCopy, err = bav.CopyUtxoView()
			if err != nil {
				return nil, errors.Wrapf(err, "ConnectBlock: error copying UtxoView")
			}
			_, _, _, _, err = utxoViewCopy.ConnectTransaction(
				txn, txHash, uint32(blockHeader.Height), blockHeader.TstampNanoSecs, verifySignatures, false)
			if err == nil {
				return nil, errors.Errorf("ConnectBlock: txn #%d should not connect but err is nil", txIndex)
			}
			var burnFee uint64
			// Connect the failing transaction to get the fees and utility fee.
			utxoOpsForTxn, burnFee, utilityFee, err = bav._connectFailingTransaction(
				txn, uint32(blockHeader.Height), verifySignatures)
			if err != nil {
				return nil, errors.Wrapf(err, "ConnectBlock: error connecting failing txn #%d", txIndex)
			}
			currentFees = burnFee + utilityFee
		}

		// After the block reward patch block height, we only include fees from transactions
		// where the transactor is not the block reward output public key. This prevents
		// the block reward output public key from being able to get their transactions
		// included in blocks for free.
		includeFeesInBlockReward := true
		if blockHeight >= uint64(bav.Params.ForkHeights.BlockRewardPatchBlockHeight) &&
			txn.TxnMeta.GetTxnType() != TxnTypeBlockReward {
			transactorPubKey, err := btcec.ParsePubKey(txn.PublicKey, btcec.S256())
			if err != nil {
				return nil, fmt.Errorf("ConnectBlock: Problem parsing transactor public key: %v", err)
			}
			includeFeesInBlockReward = !transactorPubKey.IsEqual(blockRewardOutputPublicKey)
		}

		if includeFeesInBlockReward {
			// Add the fees from this txn to the total fees. If any overflow occurs
			// mark the block as invalid and return a rule error. Note that block reward
			// txns should count as having zero fees.
			if totalFees > (math.MaxUint64 - currentFees) {
				return nil, RuleErrorTxnOutputWithInvalidAmount
			}
			totalFees += currentFees

			// For PoS, the maximum block reward is based on the maximum utility fee.
			// Add the utility fees to the max utility fees. If any overflow
			// occurs mark the block as invalid and return a rule error.
			maxUtilityFee, err = SafeUint64().Add(maxUtilityFee, utilityFee)
			if err != nil {
				return nil, errors.Wrapf(RuleErrorPoSBlockRewardWithInvalidAmount,
					"ConnectBlock: error computing maxUtilityFee: %v", err)
			}
		}

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
	if blockHeight >= uint64(bav.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		maxBlockReward = maxUtilityFee
	}
	// If the outputs of the block reward txn exceed the max block reward
	// allowed then mark the block as invalid and return an error.
	if blockRewardOutput > maxBlockReward {
		glog.Errorf("ConnectBlock(RuleErrorBlockRewardExceedsMaxAllowed): "+
			"blockRewardOutput %d exceeds maxBlockReward %d", blockRewardOutput, maxBlockReward)
		return nil, RuleErrorBlockRewardExceedsMaxAllowed
	}

	// blockLevelUtxoOps are used to track all state mutations that happen
	// after connecting all transactions in the block. These operations
	// are always the last utxo operation in a given block.
	var blockLevelUtxoOps []*UtxoOperation
	if blockHeight >= uint64(bav.Params.ForkHeights.BalanceModelBlockHeight) {
		prevNonces := bav.GetTransactorNonceEntriesToDeleteAtBlockHeight(blockHeight)
		blockLevelUtxoOps = append(blockLevelUtxoOps, &UtxoOperation{
			Type:             OperationTypeDeleteExpiredNonces,
			PrevNonceEntries: prevNonces,
		})
		for _, prevNonceEntry := range prevNonces {
			bav.DeleteTransactorNonceEntry(prevNonceEntry)
		}
	}

	// If we're past the PoS cutover, we need to track which validators were active.
	if blockHeight >= uint64(bav.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		// Get the active validators for the block.
		var signersList *bitset.Bitset
		if !desoBlock.Header.ValidatorsVoteQC.isEmpty() {
			signersList = desoBlock.Header.ValidatorsVoteQC.ValidatorsVoteAggregatedSignature.SignersList
		} else {
			signersList = desoBlock.Header.ValidatorsTimeoutAggregateQC.ValidatorsTimeoutAggregatedSignature.SignersList
		}
		allSnapshotValidators, err := bav.GetAllSnapshotValidatorSetEntriesByStake()
		if err != nil {
			return nil, errors.Wrapf(err, "ConnectBlock: error getting all snapshot validator set entries by stake")
		}
		currentEpochNumber, err := bav.GetCurrentEpochNumber()
		if err != nil {
			return nil, errors.Wrapf(err, "ConnectBlock: error getting current epoch number")
		}
		for ii, validator := range allSnapshotValidators {
			// Skip validators who didn't sign
			if !signersList.Get(ii) {
				continue
			}
			// Get the current validator entry
			validatorEntry, err := bav.GetValidatorByPKID(validator.ValidatorPKID)
			if err != nil {
				return nil, errors.Wrapf(err, "ConnectBlock: error getting validator by PKID")
			}
			// It's possible for the validator to have unregistered since two epochs ago, but is continuing
			// to vote. If the validatorEntry is nil or IsDeleted, we skip it here.
			if validatorEntry == nil || validatorEntry.IsDeleted() {
				continue
			}
			// It's possible for the validator to be in the snapshot validator set, but to have been jailed
			// in the previous epoch due to inactivity. In the edge case where the validator now comes back
			// online, we maintain its jailed status until it unjails itself explicitly again.
			if validatorEntry.Status() == ValidatorStatusJailed {
				continue
			}
			if validatorEntry.LastActiveAtEpochNumber != currentEpochNumber {
				blockLevelUtxoOps = append(blockLevelUtxoOps, &UtxoOperation{
					Type:               OperationTypeSetValidatorLastActiveAtEpoch,
					PrevValidatorEntry: validatorEntry.Copy(),
				})
				// Set the last active at epoch number to the current epoch number
				// and set the validator entry on the view.
				validatorEntry.LastActiveAtEpochNumber = currentEpochNumber
				bav._setValidatorEntryMappings(validatorEntry)
			}
		}
	}

	// If we're past the PoS Setup Fork Height, check if we should run the end of epoch hook.
	if blockHeight >= uint64(bav.Params.ForkHeights.ProofOfStake1StateSetupBlockHeight) {
		isLastBlockInEpoch, err := bav.IsLastBlockInCurrentEpoch(blockHeight)
		if err != nil {
			return nil, errors.Wrapf(err, "ConnectBlock: error checking if block is last in epoch")
		}
		if isLastBlockInEpoch {
			var utxoOperations []*UtxoOperation
			utxoOperations, err = bav.RunEpochCompleteHook(blockHeight, blockHeader.GetView(), blockHeader.TstampNanoSecs)
			if err != nil {
				return nil, errors.Wrapf(err, "ConnectBlock: error running epoch complete hook")
			}
			blockLevelUtxoOps = append(blockLevelUtxoOps, utxoOperations...)
		}
	}

	// Append all block level utxo operations to the utxo operations for the block.
	utxoOps = append(utxoOps, blockLevelUtxoOps)

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
func (bav *UtxoView) Preload(desoBlock *MsgDeSoBlock, blockHeight uint64) error {
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
		} else if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoin {
			txnMeta := txn.TxnMeta.(*DAOCoinMetadata)
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
	var daoBalances []*PGDAOCoinBalance
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
			balanceEntryKey := MakeBalanceEntryKey(balance.HolderPKID, balance.CreatorPKID)
			bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = nil

			// Fetch the creator's balance entry if they're not buying their own coin
			if !reflect.DeepEqual(txn.PublicKey, txnMeta.ProfilePublicKey) {
				balance = &PGCreatorCoinBalance{
					HolderPKID:  bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
					CreatorPKID: bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
				}
				balances = append(balances, balance)

				// We cache the balances as not present and then fill them in later
				balanceEntryKey = MakeBalanceEntryKey(balance.HolderPKID, balance.CreatorPKID)
				bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = nil
			}
		} else if txn.TxnMeta.GetTxnType() == TxnTypeDAOCoin {
			txnMeta := txn.TxnMeta.(*DAOCoinMetadata)

			// Fetch the buyer's balance entry
			daoBalance := &PGDAOCoinBalance{
				HolderPKID:  bav.GetPKIDForPublicKey(txn.PublicKey).PKID.NewPKID(),
				CreatorPKID: bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
			}
			daoBalances = append(daoBalances, daoBalance)

			// We cache the balances as not present and then fill them in later
			balanceEntryKey := MakeBalanceEntryKey(daoBalance.HolderPKID, daoBalance.CreatorPKID)
			bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry[balanceEntryKey] = nil

			// Fetch the creator's balance entry if they're not buying their own coin
			if !reflect.DeepEqual(txn.PublicKey, txnMeta.ProfilePublicKey) {
				daoBalance = &PGDAOCoinBalance{
					HolderPKID:  bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
					CreatorPKID: bav.GetPKIDForPublicKey(txnMeta.ProfilePublicKey).PKID.NewPKID(),
				}
				daoBalances = append(daoBalances, daoBalance)

				// We cache the balances as not present and then fill them in later
				balanceEntryKey = MakeBalanceEntryKey(daoBalance.HolderPKID, daoBalance.CreatorPKID)
				bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry[balanceEntryKey] = nil
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
			bav._setCreatorCoinBalanceEntryMappings(balanceEntry)
		}
	}

	if len(daoBalances) > 0 {
		foundDAOBalances := bav.Postgres.GetDAOCoinBalances(daoBalances)
		for _, daoBalance := range foundDAOBalances {
			daoBalanceEntry := daoBalance.NewBalanceEntry()
			bav._setDAOCoinBalanceEntryMappings(daoBalanceEntry)
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

func (bav *UtxoView) GetTransactorNonceEntry(nonce *DeSoNonce, pkid *PKID) (*TransactorNonceEntry, error) {
	if nonce == nil {
		return nil, fmt.Errorf("GetTransactorNonceEntry: nil nonce")
	}
	if pkid == nil {
		return nil, fmt.Errorf("GetTransactorNonceEntry: nil pkid")
	}
	mapKey := TransactorNonceMapKey{
		Nonce:          *nonce,
		TransactorPKID: *pkid,
	}

	nonceEntry, exists := bav.TransactorNonceMapKeyToTransactorNonceEntry[mapKey]
	if exists && nonceEntry != nil {
		return nonceEntry, nil
	}
	var err error
	nonceEntry, err = DbGetTransactorNonceEntry(bav.Handle, nonce, pkid)
	if err != nil {
		return nil, err
	}
	if nonceEntry == nil {
		return nil, nil
	}
	bav.TransactorNonceMapKeyToTransactorNonceEntry[mapKey] = nonceEntry
	return nonceEntry, nil

}

func (bav *UtxoView) SetTransactorNonceEntry(nonceEntry *TransactorNonceEntry) {
	if nonceEntry == nil {
		glog.Errorf("SetTransactorNonceEntry: nil nonceEntry")
		return
	}

	bav.TransactorNonceMapKeyToTransactorNonceEntry[nonceEntry.ToMapKey()] = nonceEntry
}

func (bav *UtxoView) DeleteTransactorNonceEntry(nonceEntry *TransactorNonceEntry) {
	if nonceEntry == nil {
		glog.Errorf("DeleteTransactorNonceEntry: nil nonceEntry")
		return
	}

	tombstoneEntry := nonceEntry.Copy()

	tombstoneEntry.isDeleted = true
	bav.SetTransactorNonceEntry(tombstoneEntry)
}

func (bav *UtxoView) GetTransactorNonceEntriesToDeleteAtBlockHeight(blockHeight uint64) []*TransactorNonceEntry {
	dbExpiredNonceEntries, err := DbGetTransactorNonceEntriesToExpireAtBlockHeight(bav.Handle, blockHeight)
	if err != nil {
		glog.Errorf("GetTransactorNonceEntriesToDeleteAtBlockHeight: Error fetching expired nonce entries: %v", err)
		return nil
	}
	// Add the db entries to the view
	for _, dbNonceEntry := range dbExpiredNonceEntries {
		// If the entry already exists, skip it and use what's in the view.
		if _, exists := bav.TransactorNonceMapKeyToTransactorNonceEntry[dbNonceEntry.ToMapKey()]; exists {
			continue
		}
		bav.SetTransactorNonceEntry(dbNonceEntry)
	}
	var transactorNoncesToExpire []*TransactorNonceEntry
	for _, nonceEntry := range bav.TransactorNonceMapKeyToTransactorNonceEntry {
		if nonceEntry.isDeleted {
			continue
		}
		if nonceEntry.Nonce.ExpirationBlockHeight <= blockHeight {
			transactorNoncesToExpire = append(transactorNoncesToExpire, nonceEntry)
		}
	}
	return transactorNoncesToExpire
}

func (bav *UtxoView) ConstructNonceForPublicKey(publicKey []byte, blockHeight uint64) (*DeSoNonce, error) {
	pkidEntry := bav.GetPKIDForPublicKey(publicKey)
	if pkidEntry == nil || pkidEntry.isDeleted {
		return nil, fmt.Errorf(
			"ConstructNonceForPublicKey: No PKID entry found for public key %s",
			PkToStringBoth(publicKey))
	}
	return bav.ConstructNonceForPKID(pkidEntry.PKID, blockHeight)
}

// ConstructNonceForPKID constructs a nonce for the given PKID. The depth parameter
// must be less than or equal to 2 when calling this function. We check that the
// randomly generated nonce is not already in use by the given PKID. If it is, we
// try to generate another nonce w/ depth - 1. When depth is 0 and we fail to generate
// a unique nonce, we return an error.
func (bav *UtxoView) ConstructNonceForPKID(pkid *PKID, blockHeight uint64) (*DeSoNonce, error) {
	// construct nonce
	expirationBuffer := uint64(DefaultMaxNonceExpirationBlockHeightOffset)
	if bav.GlobalParamsEntry != nil && bav.GlobalParamsEntry.MaxNonceExpirationBlockHeightOffset != 0 {
		expirationBuffer = bav.GlobalParamsEntry.MaxNonceExpirationBlockHeightOffset
	}
	// Some tests use a very low expiration buffer to test
	// that expired nonces get deleted. We don't want to
	// underflow the expiration buffer, so we only subtract
	// 10 if the expiration buffer is greater than 10.
	// We subtract 10 from the expiration buffer so that
	// nodes that are slightly behind do not reject transactions.
	if expirationBuffer > 10 {
		expirationBuffer -= 10
	}
	randomUint64, err := wire.RandomUint64()
	if err != nil {
		return nil, errors.Wrapf(err, "ConstructNonceForPKID: Error generating random uint64: ")
	}
	nonce := DeSoNonce{
		PartialID:             randomUint64,
		ExpirationBlockHeight: blockHeight + expirationBuffer,
	}

	// Make sure we don't have a collision.
	nonceEntry, err := bav.GetTransactorNonceEntry(&nonce, pkid)
	if err != nil {
		return nil, errors.Wrapf(err, "ConstructNonceForPKID: ")
	}
	if nonceEntry != nil && !nonceEntry.isDeleted {
		return nil, errors.New("ConstructNonceForPKID: Nonce already exists")
	}
	return &nonce, nil
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
		utxoEntriesForPublicKey, err = DbGetUtxosForPubKey(pkBytes, bav.Handle, bav.Snapshot)
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

// GetSpendableDeSoBalanceNanosForPublicKey gets the current spendable balance for the
// provided public key. It only considers the last block as immature currently and
// instead of the configured number of immature block rewards. Additionally, using the
// tipHash of the view only gives us access to the previous block, not the current block,
// so we are unable to mark the current block reward as immature.
// However, this bug does not introduce a security issue and is addressed with the BlockRewardPatch fork,
// but should be fixed soon.
func (bav *UtxoView) GetSpendableDeSoBalanceNanosForPublicKey(pkBytes []byte,
	tipHeight uint32) (_spendableBalance uint64, _err error) {
	// After the cut-over to Proof Of Stake, we no longer check for immature block rewards.
	// All block rewards are immediately mature.
	if tipHeight >= bav.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight {
		balanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(pkBytes)
		if err != nil {
			return 0, errors.Wrap(err, "GetSpendableDeSoBalanceNanosForPublicKey: ")
		}
		return balanceNanos, nil
	}
	// In order to get the spendable balance, we need to account for any immature block rewards.
	// We get these by starting at the chain tip and iterating backwards until we have collected
	// all the immature block rewards for this public key.
	nextBlockHash := bav.TipHash
	numImmatureBlocks := uint32(bav.Params.BlockRewardMaturity / bav.Params.TimeBetweenBlocks)
	immatureBlockRewards := uint64(0)

	if bav.Postgres != nil {
		// Note: badger is only getting the block reward for the previous block, so we make postgres
		// do the same thing. This is not ideal, but it is the simplest way to get the same behavior
		// and we will address the issue soon.
		// Filter out immature block rewards in postgres. UtxoType needs to be set correctly when importing blocks
		var startHeight uint32
		if tipHeight > 0 {
			startHeight = tipHeight - 1
		}
		// This is a special case to support tests where the number of immature blocks is 0.
		if numImmatureBlocks == 0 {
			startHeight = tipHeight
		}
		outputs := bav.Postgres.GetBlockRewardsForPublicKey(NewPublicKey(pkBytes), startHeight, tipHeight)

		var err error
		for _, output := range outputs {
			immatureBlockRewards, err = SafeUint64().Add(immatureBlockRewards, output.AmountNanos)
			if err != nil {
				return 0, errors.Wrap(err, "GetSpendableDeSoBalanceNanosForPublicKey: Problem "+
					"adding immature block rewards")
			}
		}
	} else {
		for ii := uint64(1); ii < uint64(numImmatureBlocks); ii++ {
			// Don't look up the genesis block since it isn't in the DB.
			if GenesisBlockHashHex == nextBlockHash.String() {
				break
			}

			blockNode := GetHeightHashToNodeInfo(bav.Handle, bav.Snapshot, tipHeight, nextBlockHash, false)
			if blockNode == nil {
				return 0, fmt.Errorf(
					"GetSpendableDeSoBalanceNanosForPublicKey: Problem getting block for blockhash %s",
					nextBlockHash.String())
			}
			blockRewardForPK, err := DbGetBlockRewardForPublicKeyBlockHash(bav.Handle, bav.Snapshot, pkBytes, nextBlockHash)
			if err != nil {
				return 0, errors.Wrapf(
					err, "GetSpendableDeSoBalanceNanosForPublicKey: Problem getting block reward for "+
						"public key %s blockhash %s", PkToString(pkBytes, bav.Params), nextBlockHash.String())
			}
			immatureBlockRewards, err = SafeUint64().Add(immatureBlockRewards, blockRewardForPK)
			if err != nil {
				return 0, errors.Wrapf(err, "GetSpendableDeSoBalanceNanosForPublicKey: Problem adding "+
					"block reward (%d) to immature block rewards (%d)", blockRewardForPK, immatureBlockRewards)
			}
			// TODO: This is the specific line that causes the bug. We should be using blockNode.Header.PrevBlockHash
			// instead. We are not serializing the Parent attribute when the block node is put into the DB,
			// but we do have the header. As a result, this condition always evaluates to false and thus
			// we only process the block reward for the previous block instead of all immature block rewards
			// as defined by the params.
			if blockNode.Parent != nil {
				nextBlockHash = blockNode.Parent.Hash
			} else {
				nextBlockHash = GenesisBlockHash
			}
		}
	}

	balanceNanos, err := bav.GetDeSoBalanceNanosForPublicKey(pkBytes)

	if err != nil {
		return 0, errors.Wrap(err, "GetSpendableDeSoBalanceNanosForPublicKey: ")
	}
	spendableBalanceNanos, err := SafeUint64().Sub(balanceNanos, immatureBlockRewards)
	if err != nil {
		return 0, errors.Wrapf(err,
			"GetSpendableDeSoBalanceNanosForPublicKey: error subtract immature block rewards (%d) from "+
				"balance nanos (%d)", immatureBlockRewards, balanceNanos)
	}
	return spendableBalanceNanos, nil
}

func copyExtraData(extraData map[string][]byte) map[string][]byte {
	extraDataCopy := make(map[string][]byte)
	for key, value := range extraData {
		valueCopy := make([]byte, len(value))
		copy(valueCopy, value)
		extraDataCopy[key] = valueCopy
	}
	return extraDataCopy
}

func mergeExtraData(oldMap map[string][]byte, newMap map[string][]byte) map[string][]byte {
	// Always create the map from scratch, since modifying the map on
	// newMap could modify the map on the oldMap otherwise.
	retMap := make(map[string][]byte)

	// Add the values from the oldMap
	for kk, vv := range oldMap {
		vvCopy := make([]byte, len(vv))
		copy(vvCopy, vv)
		retMap[kk] = vvCopy
	}
	// Add the values from the newMap. Allow the newMap values to overwrite the
	// oldMap values during the merge.
	for kk, vv := range newMap {
		vvCopy := make([]byte, len(vv))
		copy(vvCopy, vv)
		retMap[kk] = vvCopy
	}

	return retMap
}
