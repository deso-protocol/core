package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

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

func (bav *UtxoView) GetLikedByReader(readerPK []byte, postHash *BlockHash) bool {
	// Get like state.
	likeKey := MakeLikeKey(readerPK, *postHash)
	likeEntry := bav._getLikeEntryForLikeKey(&likeKey)
	return likeEntry != nil && !likeEntry.isDeleted
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
