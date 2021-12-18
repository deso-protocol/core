package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

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
		followExists = DbGetFollowerToFollowedMapping(bav.Handle, bav.Snapshot, &followKey.FollowerPKID, &followKey.FollowedPKID) != nil
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
