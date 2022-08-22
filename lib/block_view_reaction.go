package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) _getReactionEntryForReactionKey(reactionKey *ReactionKey) *ReactionEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.ReactionKeyToReactionEntry[*reactionKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	reactionExists := false
	if bav.Postgres != nil {
		reactionExists = bav.Postgres.GetReaction(reactionKey.ReactorPubKey[:], &reactionKey.ReactedPostHash, reactionKey.ReactEmoji) != nil
	} else {
		reactionExists = DbGetReactorPubKeyToPostHashMapping(bav.Handle, reactionKey.ReactorPubKey[:], reactionKey.ReactedPostHash, reactionKey.ReactEmoji) != nil
	}

	if reactionExists {
		reactionEntry := ReactionEntry{
			ReactorPubKey:   reactionKey.ReactorPubKey[:],
			ReactedPostHash: &reactionKey.ReactedPostHash,
			ReactEmoji:      reactionKey.ReactEmoji,
		}
		bav._setReactionEntryMappings(&reactionEntry)
		return &reactionEntry
	}

	return nil
}

func (bav *UtxoView) _setReactionEntryMappings(reactionEntry *ReactionEntry) {
	// This function shouldn't be called with nil.
	if reactionEntry == nil {
		glog.Errorf("_setReactionEntryMappings: Called with nil ReactionEntry; " +
			"this should never happen.")
		return
	}

	reactionKey := MakeReactionKey(reactionEntry.ReactorPubKey, *reactionEntry.ReactedPostHash, reactionEntry.ReactEmoji)
	bav.ReactionKeyToReactionEntry[reactionKey] = reactionEntry
}

func (bav *UtxoView) _deleteReactionEntryMappings(reactionEntry *ReactionEntry) {

	// Create a tombstone entry.
	tombstoneReactionEntry := *reactionEntry
	tombstoneReactionEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setReactionEntryMappings(&tombstoneReactionEntry)
}

func (bav *UtxoView) GetReactionByReader(readerPK []byte, postHash *BlockHash, reactEmoji rune) bool {
	// Get react state.
	reactionKey := MakeReactionKey(readerPK, *postHash, reactEmoji)
	reactionEntry := bav._getReactionEntryForReactionKey(&reactionKey)
	return reactionEntry != nil && !reactionEntry.isDeleted
}

//TODO and only update the view if the key constructed from the entry does not exist in the view yet. Otherwise, we risk updating entries in the view
// that haven't been flushed.
func (bav *UtxoView) GetReactorsForPostHash(postHash *BlockHash, reactionEmoji rune) (_ReactorPubKeys [][]byte, _err error) {
	adapter := bav.GetDbAdapter()

	if adapter.postgresDb != nil {
		reactions := adapter.postgresDb.GetReactionsForPost(postHash)
		for _, reaction := range reactions {
			bav._setReactionEntryMappings(reaction.NewReactionEntry())
		}
	} else {
		handle := adapter.badgerDb
		dbPrefix := append([]byte{}, Prefixes.PrefixPostHashToReactorPubKey...)
		dbPrefix = append(dbPrefix, postHash[:]...)
		keysFound, _ := EnumerateKeysForPrefix(handle, dbPrefix)

		// Iterate over all the db keys & values and load them into the view.
		expectedKeyLength := 1 + HashSizeBytes + btcec.PubKeyBytesLenCompressed
		for _, key := range keysFound {
			// Sanity check that this is a reasonable key.
			if len(key) != expectedKeyLength {
				return nil, fmt.Errorf("UtxoView.GetReactuibsForPostHash: Invalid key length found: %d", len(key))
			}

			reactorPubKey := key[1+HashSizeBytes:]
			reactKey := MakeReactionKey(reactorPubKey, *postHash, reactionEmoji)
			bav._getReactionEntryForReactionKey(&reactKey)
		}
	}

	// Iterate over the view and create the final list to return.
	var reactorPubKeys [][]byte
	for _, reactionEntry := range bav.ReactionKeyToReactionEntry {
		if !reactionEntry.isDeleted && reflect.DeepEqual(reactionEntry.ReactedPostHash[:], postHash[:]) {
			reactorPubKeys = append(reactorPubKeys, reactionEntry.ReactorPubKey)
		}
	}

	return reactorPubKeys, nil
}

func (bav *UtxoView) _connectReact(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeReact {
		return 0, 0, nil, fmt.Errorf("_connectReact: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*ReactMetadata)

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectReact: ")
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// At this point the inputs and outputs have been processed. Now we need to handle
	// the metadata.

	// There are two main checks that need to be done before allowing a reaction:
	//  - Check that the post exists
	//  - Check that the person hasn't already reacted with the same emoji

	//	Check that the post to react actually exists.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.PostHash)
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorCannotReactNonexistentPost,
			"_connectReact: Post hash: %v", txMeta.PostHash)
	}

	// At this point the code diverges and considers the react flows differently
	// since the presence of an existing react entry has a different effect in either case.

	reactionKey := MakeReactionKey(txn.PublicKey, *txMeta.PostHash, txMeta.EmojiReaction)
	existingReactEntry := bav._getReactionEntryForReactionKey(&reactionKey)
	// We don't need to make a copy of the post entry because all we're modifying is the emoji counts,
	// which isn't stored in any of our mappings. But we make a copy here just because it's a little bit
	// more foolproof.
	updatedPostEntry := *existingPostEntry

	if txMeta.IsRemove {
		// Ensure that there *is* an existing emoji entry to delete.
		if existingReactEntry == nil || existingReactEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorCannotRemoveReactionWithoutAnExistingReaction,
				"_connectReact: React key: %v", &reactionKey)
		}

		// Now that we know there is a react entry, we delete it and decrement the emoji count.
		bav._deleteReactionEntryMappings(existingReactEntry)
		updatedPostEntry.EmojiCount[txMeta.EmojiReaction] -= 1
	} else {
		// Ensure that there *is not* an existing react entry.
		if existingReactEntry != nil && !existingReactEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorReactEntryAlreadyExists,
				"_connectReact: Like key: %v", &reactionKey)
		}

		// Now that we know there is no pre-existing reactentry, we can create one and
		// increment the react s on the react d post.
		reactEntry := &ReactionEntry{
			ReactorPubKey:   txn.PublicKey,
			ReactedPostHash: txMeta.PostHash,
			ReactEmoji:      txMeta.EmojiReaction,
		}
		bav._setReactionEntryMappings(reactEntry)
		if updatedPostEntry.EmojiCount == nil {
			updatedPostEntry.EmojiCount = make(map[rune]uint64)
		}
		updatedPostEntry.EmojiCount[txMeta.EmojiReaction] += 1
	}

	// Set the updated post entry so it has the new emoji count.
	bav._setPostEntryMappings(&updatedPostEntry)

	// Add an operation to the list at the end indicating we've added a follow.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:           OperationTypeReact,
		PrevReactEntry: existingReactEntry,
		PrevEmojiCount: existingPostEntry.EmojiCount,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectReact(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a Reaction operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectReact: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeReact {
		return fmt.Errorf("_disconnectReact: Trying to revert "+
			"OperationTypeReact but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is a React
	txMeta := currentTxn.TxnMeta.(*ReactMetadata)

	// Before we do anything, let's get the post so we can adjust the emoji map counter later.
	reactedPostEntry := bav.GetPostEntryForPostHash(txMeta.PostHash)
	if reactedPostEntry == nil {
		return fmt.Errorf("_disconnectReact: Error getting post: %v", txMeta.PostHash)
	}

	// Here we diverge and consider the react and unreact cases separately.
	if txMeta.IsRemove {
		// If this is an remove we just need to add back the previous react entry and react
		// react count. We do some sanity checks first though to be extra safe.

		prevReactEntry := utxoOpsForTxn[operationIndex].PrevReactEntry
		// Sanity check: verify that the user on the reactEntry matches the transaction sender.
		if !reflect.DeepEqual(prevReactEntry.ReactorPubKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectReact: User public key on "+
				"ReactionEntry was %s but the PublicKey on the txn was %s",
				PkToStringBoth(prevReactEntry.ReactorPubKey),
				PkToStringBoth(currentTxn.PublicKey))
		}

		// Sanity check: verify that the post hash on the prevReactEntry matches the transaction's.
		if !reflect.DeepEqual(prevReactEntry.ReactedPostHash, txMeta.PostHash) {
			return fmt.Errorf("_disconnectLike: Liked post hash on "+
				"ReactionEntry was %s but the ReactedPostHash on the txn was %s",
				prevReactEntry.ReactedPostHash, txMeta.PostHash)
		}

		// Set the react entry and react count to their previous state.
		bav._setReactionEntryMappings(prevReactEntry)
		reactedPostEntry.EmojiCount = utxoOpsForTxn[operationIndex].PrevEmojiCount
		bav._setPostEntryMappings(reactedPostEntry)
	} else {
		// If this is a normal "react," we do some sanity checks and then delete the entry.

		// Get the ReactionEntry. If we don't find it or isDeleted=true, that's an error.
		reactKey := MakeReactionKey(currentTxn.PublicKey, *txMeta.PostHash, txMeta.EmojiReaction)
		reactEntry := bav._getReactionEntryForReactionKey(&reactKey)
		if reactEntry == nil || reactEntry.isDeleted {
			return fmt.Errorf("_disconnectReact: ReactionEntry for "+
				"reactKey %v was found to be nil or isDeleted not set appropriately: %v",
				&reactKey, reactEntry)
		}

		// Sanity check: verify that the user on the reactEntry matches the transaction sender.
		if !reflect.DeepEqual(reactEntry.ReactorPubKey, currentTxn.PublicKey) {
			return fmt.Errorf("_disconnectReact: User public key on "+
				"ReactionEntry was %s but the PublicKey on the txn was %s",
				PkToStringBoth(reactEntry.ReactorPubKey),
				PkToStringBoth(currentTxn.PublicKey))
		}

		// Sanity check: verify that the post hash on the reactEntry matches the transaction's.
		if !reflect.DeepEqual(reactEntry.ReactedPostHash, txMeta.PostHash) {
			return fmt.Errorf("_disconnectReact: Reacted post hash on "+
				"ReactionEntry was %s but the ReactedPostHash on the txn was %s",
				reactEntry.ReactedPostHash, txMeta.PostHash)
		}

		// Now that we're confident the FollowEntry lines up with the transaction we're
		// rolling back, delete the mappings and set the reaction counter to its previous value.
		bav._deleteReactionEntryMappings(reactEntry)
		reactedPostEntry.EmojiCount = utxoOpsForTxn[operationIndex].PrevEmojiCount
		bav._setPostEntryMappings(reactedPostEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the Like operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
