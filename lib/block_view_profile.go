package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"reflect"
	"sort"
	"strings"
)

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

func (bav *UtxoView) GetPKIDForPublicKey(publicKeyArg []byte) *PKIDEntry {
	// Make a copy of the publicKey to make sure it won't shift under our feet
	publicKey := publicKeyArg

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
		dbPKIDEntry := DBGetPKIDEntryForPublicKey(bav.Handle, publicKey)
		if dbPKIDEntry != nil {
			bav._setPKIDMappings(dbPKIDEntry)
		}
		return dbPKIDEntry
	}
}

func (bav *UtxoView) GetPublicKeyForPKID(pkidArg *PKID) []byte {
	// Put this check in place, since sometimes people accidentally
	// pass a pointer that shouldn't be copied.
	pkid := &PKID{}
	if pkidArg != nil {
		*pkid = *pkidArg
	}
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
		dbPublicKey := DBGetPublicKeyForPKID(bav.Handle, pkid)
		if len(dbPublicKey) != 0 {
			bav._setPKIDMappings(&PKIDEntry{
				PKID:      pkid,
				PublicKey: dbPublicKey,
			})
		}
		return dbPublicKey
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
		var daoCoinsInCirculationNanos *uint256.Int
		if profile.DAOCoinCoinsInCirculationNanos != "" {
			var err error
			daoCoinsInCirculationNanos, err = uint256.FromHex(profile.DAOCoinCoinsInCirculationNanos)
			if err != nil {
				daoCoinsInCirculationNanos = uint256.NewInt()
			}
		} else {
			daoCoinsInCirculationNanos = uint256.NewInt()
		}
		profileEntry = &ProfileEntry{
			PublicKey:   profile.PublicKey.ToBytes(),
			Username:    []byte(profile.Username),
			Description: []byte(profile.Description),
			ProfilePic:  profile.ProfilePic,
			CreatorCoinEntry: CoinEntry{
				CreatorBasisPoints:      profile.CreatorBasisPoints,
				DeSoLockedNanos:         profile.DeSoLockedNanos,
				NumberOfHolders:         profile.NumberOfHolders,
				CoinsInCirculationNanos: *uint256.NewInt().SetUint64(profile.CoinsInCirculationNanos),
				CoinWatermarkNanos:      profile.CoinWatermarkNanos,
				MintingDisabled:         profile.MintingDisabled,
			},
			DAOCoinEntry: CoinEntry{
				NumberOfHolders:           profile.DAOCoinNumberOfHolders,
				CoinsInCirculationNanos:   *daoCoinsInCirculationNanos,
				MintingDisabled:           profile.DAOCoinMintingDisabled,
				TransferRestrictionStatus: profile.DAOCoinTransferRestrictionStatus,
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
	for _, pkIter := range pubKeysMap {
		pk := pkIter
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
		return profileEntrys[ii].CreatorCoinEntry.DeSoLockedNanos > profileEntrys[jj].CreatorCoinEntry.DeSoLockedNanos
	})

	return profileEntrys
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

		if blockHeight > bav.Params.ForkHeights.UpdateProfileFixBlockHeight {
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
		// NOTE: The only pointer in here is the StakeEntry and CreatorCoinEntry pointer, but since
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
		newProfileEntry.CreatorCoinEntry.CreatorBasisPoints = txMeta.NewCreatorBasisPoints

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
		if blockHeight > bav.Params.ForkHeights.ParamUpdaterProfileUpdateFixBlockHeight {
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
				clobberedProfileBugDeSoAdjustment = clobberedProfileEntry.CreatorCoinEntry.DeSoLockedNanos
			}
		}

		newProfileEntry = ProfileEntry{
			PublicKey:   profileEntryPublicKey,
			Username:    txMeta.NewUsername,
			Description: txMeta.NewDescription,
			ProfilePic:  txMeta.NewProfilePic,

			CreatorCoinEntry: CoinEntry{
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
		fromNanos = fromProfileEntry.CreatorCoinEntry.DeSoLockedNanos
	}
	toNanos := uint64(0)
	if toProfileEntry != nil {
		toNanos = toProfileEntry.CreatorCoinEntry.DeSoLockedNanos
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

func _verifyBytesSignature(signer, data, signature []byte) error {
	bytes := Sha256DoubleHash(data)

	// Convert signature to *btcec.Signature.
	sign, err := btcec.ParseDERSignature(signature, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyBytesSignature: Problem parsing access signature: ")
	}

	// Verify signature.
	ownerPk, _ := btcec.ParsePubKey(signer, btcec.S256())
	if !sign.Verify(bytes[:], ownerPk) {
		return fmt.Errorf("_verifyBytesSignature: Invalid signature")
	}
	return nil
}

// _verifyAccessSignature verifies if the accessSignature is correct. Valid
// accessSignature is the signed hash of (derivedPublicKey + expirationBlock)
// in DER format, made with the ownerPublicKey.
func _verifyAccessSignature(ownerPublicKey []byte, derivedPublicKey []byte,
	expirationBlock uint64, accessSignature []byte) error {

	// Sanity-check and convert ownerPublicKey to *btcec.PublicKey.
	if err := IsByteArrayValidPublicKey(ownerPublicKey); err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing owner public key")
	}

	// Sanity-check and convert derivedPublicKey to *btcec.PublicKey.
	if err := IsByteArrayValidPublicKey(derivedPublicKey); err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing derived public key")
	}

	// Compute a hash of derivedPublicKey+expirationBlock.
	expirationBlockBytes := EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockBytes[:]...)
	return _verifyBytesSignature(ownerPublicKey, accessBytes, accessSignature)
}

func (bav *UtxoView) _connectAuthorizeDerivedKey(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight {
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
