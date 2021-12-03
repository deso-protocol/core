package block_view

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/davecgh/go-spew/spew"
	"github.com/deso-protocol/core/db"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
	"sort"
	"strings"
)

func (bav *UtxoView) _connectUpdateProfile(
	txn *network.MsgDeSoTxn, txHash *types.BlockHash, blockHeight uint32, verifySignatures bool,
	ignoreUtxos bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != network.TxnTypeUpdateProfile {
		return 0, 0, nil, fmt.Errorf("_connectUpdateProfile: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*network.UpdateProfileMetadata)

	// See comment on ForgivenProfileUsernameClaims. This fixes a bug in the blockchain
	// where users could claim usernames that weren't actually available.
	if forgivenUsername, exists := types.ForgivenProfileUsernameClaims[*txHash]; exists {
		// Make a copy of txMeta and assign it to the existing txMeta so we avoid
		// modifying the fields.
		newTxMeta := *txMeta
		newTxMeta.NewUsername = []byte(forgivenUsername)
		txMeta = &newTxMeta
	}

	// Validate the fields to make sure they don't exceed our limits.
	if uint64(len(txMeta.NewUsername)) > bav.Params.MaxUsernameLengthBytes {
		return 0, 0, nil, types.RuleErrorProfileUsernameTooLong
	}
	if uint64(len(txMeta.NewDescription)) > bav.Params.MaxUserDescriptionLengthBytes {
		return 0, 0, nil, types.RuleErrorProfileDescriptionTooLong
	}
	if uint64(len(txMeta.NewProfilePic)) > bav.Params.MaxProfilePicLengthBytes {
		return 0, 0, nil, types.RuleErrorMaxProfilePicSize
	}
	if txMeta.NewCreatorBasisPoints > bav.Params.MaxCreatorBasisPoints || txMeta.NewCreatorBasisPoints < 0 {
		return 0, 0, nil, types.RuleErrorProfileCreatorPercentageSize
	}
	if txMeta.NewStakeMultipleBasisPoints <= 100*100 ||
		txMeta.NewStakeMultipleBasisPoints > bav.Params.MaxStakeMultipleBasisPoints {

		return 0, 0, nil, types.RuleErrorProfileStakeMultipleSize
	}
	// If a username is set then it must adhere to a particular regex.
	if len(txMeta.NewUsername) != 0 && !types.UsernameRegex.Match(txMeta.NewUsername) {
		return 0, 0, nil, errors.Wrapf(types.RuleErrorInvalidUsername, "Username: %v", string(txMeta.NewUsername))
	}

	profilePublicKey := txn.PublicKey
	_, updaterIsParamUpdater := bav.Params.ParamUpdaterPublicKeys[MakePkMapKey(txn.PublicKey)]
	if len(txMeta.ProfilePublicKey) != 0 {
		if len(txMeta.ProfilePublicKey) != btcec.PubKeyBytesLenCompressed {
			return 0, 0, nil, errors.Wrapf(types.RuleErrorProfilePublicKeySize, "_connectUpdateProfile: %#v", txMeta.ProfilePublicKey)
		}
		_, err := btcec.ParsePubKey(txMeta.ProfilePublicKey, btcec.S256())
		if err != nil {
			return 0, 0, nil, errors.Wrapf(types.RuleErrorProfileBadPublicKey, "_connectUpdateProfile: %v", err)
		}
		profilePublicKey = txMeta.ProfilePublicKey

		if blockHeight > types.UpdateProfileFixBlockHeight {
			// Make sure that either (1) the profile pub key is the txn signer's  public key or
			// (2) the signer is a param updater
			if !reflect.DeepEqual(txn.PublicKey, txMeta.ProfilePublicKey) && !updaterIsParamUpdater {

				return 0, 0, nil, errors.Wrapf(
					types.RuleErrorProfilePubKeyNotAuthorized,
					"_connectUpdateProfile: Profile pub key: %v, signer public key: %v",
					types.PkToStringBoth(txn.PublicKey), types.PkToStringBoth(txMeta.ProfilePublicKey))
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
				types.RuleErrorProfileUsernameExists, "Username: %v, TxHashHex: %v",
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
			return 0, 0, nil, types.RuleErrorProfileUpdateRequiresNonZeroInput
		}
	}

	// See if a profile already exists for this public key.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(profilePublicKey)
	// If we are creating a profile for the first time, assess the create profile fee.
	if existingProfileEntry == nil {
		createProfileFeeNanos := bav.GlobalParamsEntry.CreateProfileFeeNanos
		totalOutput += createProfileFeeNanos
		if totalInput < totalOutput {
			return 0, 0, nil, types.RuleErrorCreateProfileTxnOutputExceedsInput
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
				types.RuleErrorProfileModificationNotAuthorized,
				"_connectUpdateProfile: Profile: %v, profile public key: %v, "+
					"txn public key: %v, paramUpdater: %v", existingProfileEntry,
				types.PkToStringBoth(existingProfileEntry.PublicKey),
				types.PkToStringBoth(txn.PublicKey), spew.Sdump(bav.Params.ParamUpdaterPublicKeys))
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
			return 0, 0, nil, types.RuleErrorProfileUsernameTooShort
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
		if blockHeight > types.ParamUpdaterProfileUpdateFixBlockHeight {
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

func (bav *UtxoView) _disconnectUpdateProfile(
	operationType OperationType, currentTxn *network.MsgDeSoTxn, txnHash *types.BlockHash,
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
	txMeta := currentTxn.TxnMeta.(*network.UpdateProfileMetadata)

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
			types.PkToString(profilePublicKey, bav.Params),
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
		dbProfileEntry := db.DBGetProfileEntryForUsername(bav.Handle, nonLowercaseUsername)
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
				PKID:      types.PublicKeyToPKID(publicKey),
				PublicKey: publicKey,
			}
			bav._setPKIDMappings(pkidEntry)
			return pkidEntry
		}

		_, pkidEntry := bav.setProfileMappings(profile)
		return pkidEntry
	} else {
		dbPKIDEntry := db.DBGetPKIDEntryForPublicKey(bav.Handle, publicKey)
		if dbPKIDEntry != nil {
			bav._setPKIDMappings(dbPKIDEntry)
		}
		return dbPKIDEntry
	}
}

func (bav *UtxoView) GetPublicKeyForPKID(pkid *types.PKID) []byte {
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
				PublicKey: types.PKIDToPublicKey(pkid),
			}
			bav._setPKIDMappings(pkidEntry)
			return pkidEntry.PublicKey
		}

		_, pkidEntry := bav.setProfileMappings(profile)
		return pkidEntry.PublicKey
	} else {
		dbPublicKey := db.DBGetPublicKeyForPKID(bav.Handle, pkid)
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

func (bav *UtxoView) GetProfileEntryForPKID(pkid *types.PKID) *ProfileEntry {
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
		dbProfileEntry := db.DBGetProfileEntryForPKID(bav.Handle, pkid)
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

// Takes a Postgres Profile, sets all the mappings on the view, returns the equivalent ProfileEntry and PKIDEntry
func (bav *UtxoView) setProfileMappings(profile *types.PGProfile) (*ProfileEntry, *PKIDEntry) {
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

// Just fetch all the profiles from the db and join them with all the profiles
// in the mempool. Then sort them by their DeSo. This can be called
// on an empty view or a view that already has a lot of transactions
// applied to it.
func (bav *UtxoView) GetAllProfiles(readerPK []byte) (
	_profiles map[PkMapKey]*ProfileEntry,
	_corePostsByProfilePublicKey map[PkMapKey][]*PostEntry,
	_commentsByProfilePublicKey map[PkMapKey][]*PostEntry,
	_postEntryReaderStates map[types.BlockHash]*PostEntryReaderState, _err error) {
	// Start by fetching all the profiles we have in the db.
	//
	// TODO(performance): This currently fetches all profiles. We should implement
	// some kind of pagination instead though.
	_, _, dbProfileEntries, err := db.DBGetAllProfilesByCoinValue(bav.Handle, true /*fetchEntries*/)
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
		_, dbCommentHashes, _, err := db.DBGetCommentPostHashesForParentStakeID(
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
	_, _, dbPostEntries, err := db.DBGetAllPostsByTstamp(bav.Handle, true /*fetchEntries*/)
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
	postEntryReaderStates := make(map[types.BlockHash]*PostEntryReaderState)
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
