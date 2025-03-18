package lib

import (
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/dgraph-io/badger/v4"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

func (bav *UtxoView) FlushToDb(blockHeight uint64) error {
	// Make sure everything happens inside a single transaction.
	var err error
	if bav.Postgres != nil {
		err = bav.Postgres.FlushView(bav, blockHeight)
		if err != nil {
			return err
		}
	}

	err = bav.Handle.Update(func(txn *badger.Txn) error {
		return bav.FlushToDbWithTxn(txn, blockHeight)
	})
	if err != nil {
		return err
	}

	// After a successful flush, reset the in-memory mappings for the view
	// so that it can be re-used if desired.
	//
	// Note that the TipHash does not get reset as part of _ResetViewMappingsAfterFlush because
	// it is not something that is affected by a flush operation. Moreover, its value
	// is consistent with the view regardless of whether or not the view is flushed or
	// not.
	bav._ResetViewMappingsAfterFlush()

	return nil
}

func (bav *UtxoView) FlushToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// We're about to flush records to the main DB, so we initiate the snapshot update.
	// This function prepares the data structures in the snapshot.
	if bav.Snapshot != nil {
		bav.Snapshot.PrepareAncestralRecordsFlush()
	}

	err := bav.FlushToDBWithoutAncestralRecordsFlushWithTxn(txn, blockHeight)
	if err != nil {
		return err
	}
	// We can exit early if we're not using a snapshot.
	if bav.Snapshot == nil {
		return nil
	}
	// Flush the ancestral records to the DB.
	err = bav.Snapshot.FlushAncestralRecordsWithTxn(txn)
	if err != nil {
		return err
	}
	return nil
}

// FlushToDBWithoutAncestralRecordsFlushWithTxn flushes the UtxoView to the DB without
// calling PrepareAncestralRecordsFlush. This SHOULD ONLY be used when flushing the
// view within a badger transaction that itself calls PrepareAncestralRecordsFlush
// and defer StartAncestralRecordsFlush.
func (bav *UtxoView) FlushToDBWithoutAncestralRecordsFlushWithTxn(txn *badger.Txn, blockHeight uint64) error {

	// Only flush to BadgerDB if Postgres is disabled
	if bav.Postgres == nil {
		if err := bav._flushUtxosToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushProfileEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushPKIDEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushPostEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushLikeEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushFollowEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushDiamondEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushMessageEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushBalanceEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushDAOCoinBalanceEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushDeSoBalancesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushForbiddenPubKeyEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushNFTEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushNFTBidEntriesToDbWithTxn(txn); err != nil {
			return err
		}
		if err := bav._flushDerivedKeyEntryToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushAccessGroupEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushAccessGroupMembersToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushNewMessageEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		// Temporarily flush all DAO Coin Limit orders to badger
		//if err := bav._flushDAOCoinLimitOrderEntriesToDbWithTxn(txn, blockHeight); err != nil {
		//	return err
		//}
		if err := bav._flushUserAssociationEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
		if err := bav._flushPostAssociationEntriesToDbWithTxn(txn, blockHeight); err != nil {
			return err
		}
	}

	// Always flush to BadgerDB.
	if err := bav._flushBitcoinExchangeDataWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushGlobalParamsEntryToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushAcceptedBidEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushRepostEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushMessagingGroupEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	// Temporarily flush all DAO Coin Limit orders to badger
	if err := bav._flushDAOCoinLimitOrderEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushNonceEntriesToDbWithTxn(txn); err != nil {
		return err
	}
	if err := bav._flushLockedBalanceEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushLockupYieldCurvePointEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushValidatorEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushValidatorBLSPublicKeyPKIDPairEntryMappingsWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushStakeEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushLockedStakeEntriesToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	// TODO: We may want to move this into a new FlushToDb function that only flushes
	// entries set in the OnEpochEndHook. No sense in wasting a bunch of cycles flushing
	// all the other entries which will always be nil/empty in the OnEpochEndHook.
	if err := bav._flushCurrentEpochEntryToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushCurrentRandomSeedHashToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushSnapshotGlobalParamsEntryToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushSnapshotValidatorSetToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushSnapshotLeaderScheduleToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushSnapshotStakesToRewardToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	if err := bav._flushSnapshotValidatorBLSPublicKeyPKIDPairEntryToDbWithTxn(txn, blockHeight); err != nil {
		return err
	}
	return nil
}

func (bav *UtxoView) _flushUtxosToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushUtxosToDbWithTxn: flushing %d mappings", len(bav.UtxoKeyToUtxoEntry))

	for utxoKeyIter, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter

		// As a sanity-check, make sure the back-reference for each entry
		// points to its key.
		if utxoEntry.UtxoKey == nil || *utxoEntry.UtxoKey != utxoKey {
			return fmt.Errorf("_flushUtxosToDbWithTxn: Found utxoEntry %+v for "+
				"utxoKey %v has invalid back-refernce utxoKey %v",
				utxoEntry, utxoKey, utxoEntry.UtxoKey)
		}

		// Start by deleting the pre-existing mappings in the db for this key if they
		// have not yet been modified.
		if err := DeleteUnmodifiedMappingsForUtxoWithTxn(txn, bav.Snapshot, &utxoKey, bav.EventManager, utxoEntry.isSpent); err != nil {
			return err
		}
	}
	numDeleted := 0
	numPut := 0
	for utxoKeyIter, utxoEntry := range bav.UtxoKeyToUtxoEntry {
		// Make a copy of the iterator since it might change from under us.
		utxoKey := utxoKeyIter

		if utxoEntry.isSpent {
			numDeleted++
			// If an entry is spent then there's nothing to do, since the mappings in
			// the db have already been deleted.
		} else {
			numPut++
			// If the entry is unspent, then we need to re-set its mappings in the db
			// appropriately.
			if err := PutMappingsForUtxoWithTxn(txn, bav.Snapshot, blockHeight, &utxoKey, utxoEntry, bav.EventManager); err != nil {
				return err
			}
		}
	}

	glog.V(2).Infof("_flushUtxosToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// Now update the number of entries in the db with confidence.
	if err := PutUtxoNumEntriesWithTxn(txn, bav.Snapshot, bav.NumUtxoEntries, bav.EventManager); err != nil {
		return err
	}

	// At this point, the db's position index should be updated and the (key -> entry)
	// index should be updated to remove all spent utxos. The number of entries field
	// in the db should also be accurate.

	return nil
}

func (bav *UtxoView) _flushDeSoBalancesToDbWithTxn(txn *badger.Txn) error {
	glog.V(2).Infof("_flushDeSoBalancesToDbWithTxn: flushing %d mappings",
		len(bav.PublicKeyToDeSoBalanceNanos))

	for pubKeyIter, balanceNanos := range bav.PublicKeyToDeSoBalanceNanos {
		// Make a copy of the iterator since it might change from under us.
		pubKey := pubKeyIter[:]

		// Start by deleting the pre-existing mappings in the db for this key if they
		// have not yet been modified.
		if err := DbDeletePublicKeyToDeSoBalanceWithTxn(txn, bav.Snapshot, pubKey, bav.EventManager, balanceNanos == 0); err != nil {
			return err
		}
	}
	for pubKeyIter, balanceNanos := range bav.PublicKeyToDeSoBalanceNanos {
		// Make a copy of the iterator since it might change from under us.
		pubKey := pubKeyIter[:]

		if balanceNanos > 0 {
			if err := DbPutDeSoBalanceForPublicKeyWithTxn(txn, bav.Snapshot, pubKey, balanceNanos, bav.EventManager); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushGlobalParamsEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	globalParamsEntry := bav.GlobalParamsEntry
	if err := DbPutGlobalParamsEntryWithTxn(txn, bav.Snapshot, blockHeight, *globalParamsEntry, bav.EventManager); err != nil {
		return errors.Wrapf(err, "_flushGlobalParamsEntryToDbWithTxn: Problem putting global params entry in DB")
	}
	return nil
}

func (bav *UtxoView) _flushForbiddenPubKeyEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the KeyTorepostEntry map.
	for _, forbiddenPubKeyEntry := range bav.ForbiddenPubKeyToForbiddenPubKeyEntry {
		// Delete the existing mappings in the db for this ForbiddenPubKeyEntry. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteForbiddenBlockSignaturePubKeyWithTxn(txn, bav.Snapshot, forbiddenPubKeyEntry.PubKey[:], bav.EventManager, forbiddenPubKeyEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushForbiddenPubKeyEntriesToDbWithTxn: Problem deleting "+
					"forbidden public key: %v: ", &forbiddenPubKeyEntry.PubKey)
		}
	}
	for _, forbiddenPubKeyEntry := range bav.ForbiddenPubKeyToForbiddenPubKeyEntry {
		if forbiddenPubKeyEntry.isDeleted {
			// If the ForbiddenPubKeyEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the ForbiddenPubKeyEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutForbiddenBlockSignaturePubKeyWithTxn(txn, bav.Snapshot, forbiddenPubKeyEntry.PubKey, bav.EventManager); err != nil {

				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushBitcoinExchangeDataWithTxn(txn *badger.Txn) error {
	// Iterate through our in-memory map. If anything has a value of false it means
	// that particular mapping should be expunged from the db. If anything has a value
	// of true it means that mapping should be added to the db.
	for bitcoinBurnTxIDIter, mappingExists := range bav.BitcoinBurnTxIDs {
		// Be paranoid and copy the iterator in case anything takes a reference below.
		bitcoinBurnTxID := bitcoinBurnTxIDIter

		if mappingExists {
			// In this case we should add the mapping to the db.
			if err := DbPutBitcoinBurnTxIDWithTxn(txn, bav.Snapshot, &bitcoinBurnTxID, bav.EventManager); err != nil {
				return errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
					"Problem putting BitcoinBurnTxID %v to db", &bitcoinBurnTxID)
			}
		} else {
			// In this case we should delete the mapping from the db.
			if err := DbDeleteBitcoinBurnTxIDWithTxn(txn, bav.Snapshot, &bitcoinBurnTxID, bav.EventManager, true); err != nil {
				return errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
					"Problem deleting BitcoinBurnTxID %v to db", &bitcoinBurnTxID)
			}
		}
	}

	// Update NanosPurchased
	if err := DbPutNanosPurchasedWithTxn(txn, bav.Snapshot, bav.NanosPurchased, bav.EventManager); err != nil {
		errors.Wrapf(err, "UtxoView._flushBitcoinExchangeDataWithTxn: "+
			"Problem putting NanosPurchased %d to db", bav.NanosPurchased)
	}

	// Update the BitcoinUSDExchangeRate in the db
	if err := DbPutUSDCentsPerBitcoinExchangeRateWithTxn(txn, bav.Snapshot, bav.USDCentsPerBitcoin, bav.EventManager); err != nil {
		errors.Wrapf(err, "UtxoView.FlushToDBWithTxn: "+
			"Problem putting USDCentsPerBitcoin %d to db", bav.USDCentsPerBitcoin)
	}

	// DB should be fully up to date as far as BitcoinBurnTxIDs and NanosPurchased go.
	return nil
}

func (bav *UtxoView) _flushMessageEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Go through all the entries in the MessageKeyToMessageEntry map.
	for messageKeyIter, messageEntry := range bav.MessageKeyToMessageEntry {
		// Make a copy of the iterator since we take references to it below.
		messageKey := messageKeyIter

		// Delete the existing mappings in the db for this MessageKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteMessageEntryMappingsWithTxn(txn, bav.Snapshot, messageKey.PublicKey[:], messageKey.TstampNanos, bav.EventManager, messageEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushMessageEntriesToDbWithTxn: Problem deleting mappings "+
					"for MessageKey: %v: ", &messageKey)
		}

		if messageEntry.isDeleted {
			// If the MessageEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the MessageEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutMessageEntryWithTxn(txn, bav.Snapshot, blockHeight, messageKey, messageEntry, bav.EventManager); err != nil {
				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushRepostEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {

	// Go through all the entries in the repostKeyTorepostEntry map.
	for repostKeyIter, repostEntry := range bav.RepostKeyToRepostEntry {
		// Make a copy of the iterator since we make references to it below.
		repostKey := repostKeyIter

		// Sanity-check that the RepostKey computed from the RepostEntry is
		// equal to the RepostKey that maps to that entry.
		repostKeyInEntry := MakeRepostKey(repostEntry.ReposterPubKey, *repostEntry.RepostedPostHash)
		if repostKeyInEntry != repostKey {
			return fmt.Errorf("_flushRepostEntriesToDbWithTxn: RepostEntry has "+
				"RepostKey: %v, which doesn't match the RepostKeyToRepostEntry map key %v",
				&repostKeyInEntry, &repostKey)
		}

		// Delete the existing mappings in the db for this RepostKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteRepostMappingsWithTxn(txn, bav.Snapshot, *repostEntry, bav.EventManager, repostEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushRepostEntriesToDbWithTxn: Problem deleting mappings "+
					"for RepostKey: %v: ", &repostKey)
		}
	}
	for _, repostEntry := range bav.RepostKeyToRepostEntry {
		if repostEntry.isDeleted {
			// If the RepostedEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the RepostEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutRepostMappingsWithTxn(txn, bav.Snapshot, blockHeight, *repostEntry, bav.EventManager); err != nil {

				return err
			}
		}
	}

	// At this point all of the RepostEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushLikeEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the LikeKeyToLikeEntry map.
	for likeKeyIter, likeEntry := range bav.LikeKeyToLikeEntry {
		// Make a copy of the iterator since we make references to it below.
		likeKey := likeKeyIter

		// Sanity-check that the LikeKey computed from the LikeEntry is
		// equal to the LikeKey that maps to that entry.
		likeKeyInEntry := MakeLikeKey(likeEntry.LikerPubKey, *likeEntry.LikedPostHash)
		if likeKeyInEntry != likeKey {
			return fmt.Errorf("_flushLikeEntriesToDbWithTxn: LikeEntry has "+
				"LikeKey: %v, which doesn't match the LikeKeyToLikeEntry map key %v",
				&likeKeyInEntry, &likeKey)
		}

		// Delete the existing mappings in the db for this LikeKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteLikeMappingsWithTxn(txn, bav.Snapshot, likeKey.LikerPubKey[:], likeKey.LikedPostHash, bav.EventManager, likeEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushLikeEntriesToDbWithTxn: Problem deleting mappings "+
					"for LikeKey: %v: ", &likeKey)
		}
	}

	// Go through all the entries in the LikeKeyToLikeEntry map.
	for _, likeEntry := range bav.LikeKeyToLikeEntry {

		if likeEntry.isDeleted {
			// If the LikeEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the LikeEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutLikeMappingsWithTxn(txn, bav.Snapshot, likeEntry.LikerPubKey, *likeEntry.LikedPostHash, bav.EventManager); err != nil {

				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushFollowEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through all the entries in the FollowKeyToFollowEntry map.
	for followKeyIter, followEntry := range bav.FollowKeyToFollowEntry {
		// Make a copy of the iterator since we make references to it below.
		followKey := followKeyIter

		// Sanity-check that the FollowKey computed from the FollowEntry is
		// equal to the FollowKey that maps to that entry.
		followKeyInEntry := MakeFollowKey(
			followEntry.FollowerPKID, followEntry.FollowedPKID)
		if followKeyInEntry != followKey {
			return fmt.Errorf("_flushFollowEntriesToDbWithTxn: FollowEntry has "+
				"FollowKey: %v, which doesn't match the FollowKeyToFollowEntry map key %v",
				&followKeyInEntry, &followKey)
		}

		// Delete the existing mappings in the db for this FollowKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteFollowMappingsWithTxn(txn, bav.Snapshot, followEntry.FollowerPKID, followEntry.FollowedPKID, bav.EventManager, followEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushFollowEntriesToDbWithTxn: Problem deleting mappings "+
					"for FollowKey: %v: ", &followKey)
		}
	}

	// Go through all the entries in the FollowKeyToFollowEntry map.
	for _, followEntry := range bav.FollowKeyToFollowEntry {
		if followEntry.isDeleted {
			// If the FollowEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the FollowEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutFollowMappingsWithTxn(txn, bav.Snapshot, followEntry.FollowerPKID, followEntry.FollowedPKID, bav.EventManager); err != nil {

				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushNFTEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {

	// Go through and delete all the entries so they can be added back fresh.
	for nftKeyIter, nftEntry := range bav.NFTKeyToNFTEntry {
		// Make a copy of the iterator since we make references to it below.
		nftKey := nftKeyIter

		// Sanity-check that the NFTKey computed from the NFTEntry is
		// equal to the NFTKey that maps to that entry.
		nftKeyInEntry := MakeNFTKey(nftEntry.NFTPostHash, nftEntry.SerialNumber)
		if nftKeyInEntry != nftKey {
			return fmt.Errorf("_flushNFTEntriesToDbWithTxn: NFTEntry has "+
				"NFTKey: %v, which doesn't match the NFTKeyToNFTEntry map key %v",
				&nftKeyInEntry, &nftKey)
		}

		// Delete the existing mappings in the db for this NFTKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteNFTMappingsWithTxn(txn, bav.Snapshot, nftEntry.NFTPostHash, nftEntry.SerialNumber, bav.EventManager, nftEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushNFTEntriesToDbWithTxn: Problem deleting mappings "+
					"for NFTKey: %v: ", &nftKey)
		}
	}

	// Add back all of the entries that aren't deleted.
	for _, nftEntry := range bav.NFTKeyToNFTEntry {
		if nftEntry.isDeleted {
			// If the NFTEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the NFTEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutNFTEntryMappingsWithTxn(txn, bav.Snapshot, blockHeight, nftEntry, bav.EventManager); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushAcceptedBidEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {

	// Go through and delete all the entries so they can be added back fresh.
	for nftKeyIter, acceptedNFTBidEntries := range bav.NFTKeyToAcceptedNFTBidHistory {
		// Make a copy of the iterator since we make references to it below.
		nftKey := nftKeyIter

		// If the acceptedNFTBidEntries is nil or empty, then we set entryIsDeleted to true, so that the change is
		// reflected by the state syncer.
		entryIsDeleted := acceptedNFTBidEntries == nil || len(*acceptedNFTBidEntries) == 0

		// We skip the standard sanity check.  Since it is possible to accept a bid on serial number 0, it is possible
		// that none of the accepted bids have the same serial number as the key.

		// Delete the existing mappings in the db for this NFTKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteAcceptedNFTBidEntriesMappingsWithTxn(txn, bav.Snapshot, &nftKey.NFTPostHash, nftKey.SerialNumber, bav.EventManager, entryIsDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushAcceptedBidEntriesToDbWithTxn: Problem deleting mappings "+
					"for NFTKey: %v: ", &nftKey)
		}
	}

	// Add back all of the entries that aren't nil or of length 0
	for nftKeyIter, acceptedNFTBidEntries := range bav.NFTKeyToAcceptedNFTBidHistory {
		nftKey := nftKeyIter
		if acceptedNFTBidEntries == nil || len(*acceptedNFTBidEntries) == 0 {
			// If the acceptedNFTBidEntries is nil or has length 0 then there's nothing to do because
			// we already deleted the entry above. length 0 means that there are no accepted bids yet.
		} else {
			// If the NFTEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutAcceptedNFTBidEntriesMappingWithTxn(txn, bav.Snapshot, blockHeight, nftKey, acceptedNFTBidEntries, bav.EventManager); err != nil {

				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushNFTBidEntriesToDbWithTxn(txn *badger.Txn) error {

	// Go through and delete all the entries so they can be added back fresh.
	for nftBidKeyIter, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		// Make a copy of the iterator since we make references to it below.
		nftBidKey := nftBidKeyIter

		// Sanity-check that the NFTBidKey computed from the NFTBidEntry is
		// equal to the NFTBidKey that maps to that entry.
		nftBidKeyInEntry := MakeNFTBidKey(
			nftBidEntry.BidderPKID, nftBidEntry.NFTPostHash, nftBidEntry.SerialNumber)
		if nftBidKeyInEntry != nftBidKey {
			return fmt.Errorf("_flushNFTBidEntriesToDbWithTxn: NFTBidEntry has "+
				"NFTBidKey: %v, which doesn't match the NFTBidKeyToNFTEntry map key %v",
				&nftBidKeyInEntry, &nftBidKey)
		}

		// Delete the existing mappings in the db for this NFTBidKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteNFTBidMappingsWithTxn(txn, bav.Snapshot, &nftBidKey, bav.EventManager, nftBidEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushNFTBidEntriesToDbWithTxn: Problem deleting mappings "+
					"for NFTBidKey: %v: ", &nftBidKey)
		}
	}

	// Add back all of the entries that aren't deleted.
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if nftBidEntry.isDeleted {
			// If the NFTEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the NFTEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutNFTBidEntryMappingsWithTxn(txn, bav.Snapshot, nftBidEntry, bav.EventManager); err != nil {
				return err
			}
		}
	}

	return nil
}

func (bav *UtxoView) _flushDiamondEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {

	// Go through and delete all the entries so they can be added back fresh.
	for diamondKeyIter, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		// Make a copy of the iterator since we make references to it below.
		diamondKey := diamondKeyIter

		// Sanity-check that the DiamondKey computed from the DiamondEntry is
		// equal to the DiamondKey that maps to that entry.
		diamondKeyInEntry := MakeDiamondKey(
			diamondEntry.SenderPKID, diamondEntry.ReceiverPKID, diamondEntry.DiamondPostHash)
		if diamondKeyInEntry != diamondKey {
			return fmt.Errorf("_flushDiamondEntriesToDbWithTxn: DiamondEntry has "+
				"DiamondKey: %v, which doesn't match the DiamondKeyToDiamondEntry map key %v",
				&diamondKeyInEntry, &diamondKey)
		}

		// Delete the existing mappings in the db for this DiamondKey. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteDiamondMappingsWithTxn(txn, bav.Snapshot, diamondEntry, bav.EventManager, diamondEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushDiamondEntriesToDbWithTxn: Problem deleting mappings "+
					"for DiamondKey: %v: ", &diamondKey)
		}
	}

	// Add back all of the entries that aren't deleted.
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			// If the DiamondEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// If the DiamondEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DbPutDiamondMappingsWithTxn(txn, bav.Snapshot, blockHeight, diamondEntry, bav.EventManager); err != nil {

				return err
			}
		}
	}

	// At this point all of the MessageEntry mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushPostEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// TODO(DELETEME): Remove flush logging after debugging MarkBlockInvalid bug.
	glog.V(2).Infof("_flushPostEntriesToDbWithTxn: flushing %d mappings", len(bav.PostHashToPostEntry))

	// Go through all the entries in the PostHashToPostEntry map.
	for postHashIter, postEntry := range bav.PostHashToPostEntry {
		// Make a copy of the iterator since we take references to it below.
		postHash := postHashIter

		// Sanity-check that the hash in the post is the same as the hash in the
		// entry
		if postHash != *postEntry.PostHash {
			return fmt.Errorf("_flushPostEntriesToDbWithTxn: PostEntry has "+
				"PostHash: %v, neither of which match "+
				"the PostHashToPostEntry map key %v",
				postHash, postEntry.PostHash)
		}

		// Delete the existing mappings in the db for this PostHash. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeletePostEntryMappingsWithTxn(txn, bav.Snapshot, &postHash, bav.Params, bav.EventManager, postEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushPostEntriesToDbWithTxn: Problem deleting mappings "+
					"for PostHash: %v: ", postHash)
		}
	}
	numDeleted := 0
	numPut := 0
	for _, postEntry := range bav.PostHashToPostEntry {
		if postEntry.isDeleted {
			numDeleted++
			// If the PostEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// If the PostEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutPostEntryMappingsWithTxn(txn, bav.Snapshot, blockHeight, postEntry, bav.Params, bav.EventManager); err != nil {

				return err
			}
		}
	}

	// TODO(DELETEME): Remove flush logging after debugging MarkBlockInvalid bug.
	glog.V(2).Infof("_flushPostEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the PostEntry mappings in the db should be up-to-date.

	return nil
}
func (bav *UtxoView) _flushPKIDEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	for pubKeyIter, pkidEntry := range bav.PublicKeyToPKIDEntry {
		pubKeyCopy := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(pubKeyCopy, pubKeyIter[:])

		// Delete the existing mappings in the db for this PKID. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeletePKIDMappingsWithTxn(txn, bav.Snapshot, pubKeyCopy, bav.Params, bav.EventManager, pkidEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushPKIDEntriesToDbWithTxn: Problem deleting mappings "+
					"for pkid: %v, public key: %v: ", PkToString(pkidEntry.PKID[:], bav.Params),
				PkToString(pubKeyCopy, bav.Params))
		}
	}

	// Go through all the entries in the ProfilePublicKeyToProfileEntry map.
	for pubKeyIter, pkidEntry := range bav.PublicKeyToPKIDEntry {
		pubKeyCopy := make([]byte, btcec.PubKeyBytesLenCompressed)
		copy(pubKeyCopy, pubKeyIter[:])

		if pkidEntry.isDeleted {
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			// Sanity-check that the public key in the entry matches the public key in
			// the mapping.
			if !reflect.DeepEqual(pubKeyCopy, pkidEntry.PublicKey) {
				return fmt.Errorf("_flushPKIDEntriesToDbWithTxn: Sanity-check failed. "+
					"Public key in entry %v does not match public key in mapping %v ",
					PkToString(pkidEntry.PublicKey[:], bav.Params),
					PkToString(pubKeyCopy, bav.Params))
			}
			// Sanity-check that the mapping in the public key map lines up with the mapping
			// in the PKID map.
			if _, pkidEntryExists := bav.PKIDToPublicKey[*pkidEntry.PKID]; !pkidEntryExists {
				return fmt.Errorf("_flushPKIDEntriesToDbWithTxn: Sanity-check failed. "+
					"PKID %v for public key %v does not exist in PKIDToPublicKey map.",
					PkToString(pkidEntry.PKID[:], bav.Params),
					PkToString(pubKeyCopy, bav.Params))
			}

			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutPKIDMappingsWithTxn(txn, bav.Snapshot, blockHeight, pubKeyCopy, pkidEntry, bav.Params, bav.EventManager); err != nil {

				return err
			}
		}
	}

	// At this point all of the PKIDEntry mappings in the db should be up-to-date.
	return nil
}

func (bav *UtxoView) _flushProfileEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushProfilesToDbWithTxn: flushing %d mappings", len(bav.ProfilePKIDToProfileEntry))

	// Go through all the entries in the ProfilePublicKeyToProfileEntry map.
	for profilePKIDIter, profileEntry := range bav.ProfilePKIDToProfileEntry {
		// Make a copy of the iterator since we take references to it below.
		profilePKID := profilePKIDIter

		// Delete the existing mappings in the db for this PKID. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteProfileEntryMappingsWithTxn(txn, bav.Snapshot, &profilePKID, bav.Params, bav.EventManager, profileEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushProfileEntriesToDbWithTxn: Problem deleting mappings "+
					"for pkid: %v, public key: %v: ", PkToString(profilePKID[:], bav.Params),
				PkToString(profileEntry.PublicKey, bav.Params))
		}
	}
	numDeleted := 0
	numPut := 0
	for profilePKIDIter, profileEntry := range bav.ProfilePKIDToProfileEntry {
		// Make a copy of the iterator since we take references to it below.
		profilePKID := profilePKIDIter

		if profileEntry.isDeleted {
			numDeleted++
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// Get the PKID according to another map in the view and
			// sanity-check that it lines up.
			viewPKIDEntry := bav.GetPKIDForPublicKey(profileEntry.PublicKey)
			if viewPKIDEntry == nil || viewPKIDEntry.isDeleted || *viewPKIDEntry.PKID != profilePKID {
				return fmt.Errorf("_flushProfileEntriesToDbWithTxn: Sanity-check failed: PKID %v does "+
					"not exist in view mapping for profile with public key %v",
					PkToString(profilePKID[:], bav.Params),
					PkToString(profileEntry.PublicKey, bav.Params))
			}

			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutProfileEntryMappingsWithTxn(txn, bav.Snapshot, blockHeight, profileEntry, &profilePKID, bav.Params, bav.EventManager); err != nil {

				return err
			}
		}
	}

	glog.V(2).Infof("_flushProfilesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the PostEntry mappings in the db should be up-to-date.

	return nil
}

// TODO: All of these functions should be renamed "CreatorCoinBalanceEntry" to
// distinguish them from DAOCoinBalanceEntry, which is a different but similar index
// that got introduced later.
func (bav *UtxoView) _flushBalanceEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushBalanceEntriesToDbWithTxn: flushing %d mappings", len(bav.HODLerPKIDCreatorPKIDToBalanceEntry))

	// Go through all the entries in the HODLerPubKeyCreatorPubKeyToBalanceEntry map.
	for balanceKeyIter, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		// Make a copy of the iterator since we take references to it below.
		balanceKey := balanceKeyIter

		// Sanity-check that the balance key in the map is the same
		// as the public key in the entry.
		computedBalanceKey := MakeBalanceEntryKey(
			balanceEntry.HODLerPKID, balanceEntry.CreatorPKID)
		if !reflect.DeepEqual(balanceKey, computedBalanceKey) {
			return fmt.Errorf("_flushBalanceEntriesToDbWithTxn: BalanceEntry has "+
				"map key: %v which does not match match "+
				"the HODLerPubKeyCreatorPubKeyToBalanceEntry map key %v",
				balanceKey, computedBalanceKey)
		}

		// Delete the existing mappings in the db for this balance key. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteBalanceEntryMappingsWithTxn(txn, bav.Snapshot, &(balanceKey.HODLerPKID), &(balanceKey.CreatorPKID), false, bav.EventManager, balanceEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushBalanceEntriesToDbWithTxn: Problem deleting mappings "+
					"for public key: %v: ", balanceKey)
		}
	}
	numDeleted := 0
	numPut := 0
	// Go through all the entries in the HODLerPubKeyCreatorPubKeyToBalanceEntry map.
	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToBalanceEntry {
		// Make a copy of the iterator since we take references to it below.
		if balanceEntry.isDeleted {
			numDeleted++
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutBalanceEntryMappingsWithTxn(txn, bav.Snapshot, blockHeight, balanceEntry, false, bav.EventManager); err != nil {

				return err
			}
		}
	}

	glog.V(2).Infof("_flushBalanceEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the creator coin mappings in the db should be up-to-date.

	return nil
}

// TODO: This could theoretically be consolidated with the other BalanceEntry flusher.
func (bav *UtxoView) _flushDAOCoinBalanceEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushDAOCoinBalanceEntriesToDbWithTxn: flushing %d mappings", len(bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry))

	// Go through all the entries in the HODLerPubKeyCreatorPubKeyToBalanceEntry map.
	for balanceKeyIter, balanceEntry := range bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry {
		// Make a copy of the iterator since we take references to it below.
		balanceKey := balanceKeyIter

		// Sanity-check that the balance key in the map is the same
		// as the public key in the entry.
		computedBalanceKey := MakeBalanceEntryKey(
			balanceEntry.HODLerPKID, balanceEntry.CreatorPKID)
		if !reflect.DeepEqual(balanceKey, computedBalanceKey) {
			return fmt.Errorf("_flushDAOCoinBalanceEntriesToDbWithTxn: BalanceEntry has "+
				"map key: %v which does not match match "+
				"the HODLerPubKeyCreatorPubKeyToBalanceEntry map key %v",
				balanceKey, computedBalanceKey)
		}

		// Delete the existing mappings in the db for this balance key. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteBalanceEntryMappingsWithTxn(txn, bav.Snapshot, &(balanceKey.HODLerPKID), &(balanceKey.CreatorPKID), true, bav.EventManager, balanceEntry.isDeleted); err != nil {

			return errors.Wrapf(
				err, "_flushDAOCoinBalanceEntriesToDbWithTxn: Problem deleting mappings "+
					"for public key: %v: ", balanceKey)
		}
	}
	numDeleted := 0
	numPut := 0
	// Go through all the entries in the HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry map.
	for _, balanceEntry := range bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry {
		// Make a copy of the iterator since we take references to it below.
		if balanceEntry.isDeleted {
			numDeleted++
			// If the ProfileEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// If the ProfileEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutBalanceEntryMappingsWithTxn(txn, bav.Snapshot, blockHeight, balanceEntry, true, bav.EventManager); err != nil {

				return err
			}
		}
	}

	glog.V(2).Infof("_flushDAOCoinBalanceEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the DAO coin mappings in the db should be up-to-date.

	return nil
}

func (bav *UtxoView) _flushDerivedKeyEntryToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushDerivedKeyEntryToDbWithTxn: flushing %d mappings", len(bav.DerivedKeyToDerivedEntry))
	numDeleted := 0
	numPut := 0

	// Go through all entries in the DerivedKeyToDerivedEntry map and add them to the DB.
	for derivedKeyMapKey, derivedKeyEntry := range bav.DerivedKeyToDerivedEntry {
		// Delete the existing mapping in the DB for this map key, this will be re-added
		// later if isDeleted=false.
		if err := DBDeleteDerivedKeyMappingWithTxn(txn, bav.Snapshot, derivedKeyMapKey.OwnerPublicKey, derivedKeyMapKey.DerivedPublicKey, bav.EventManager, derivedKeyEntry.isDeleted); err != nil {

			return errors.Wrapf(err, "UtxoView._flushDerivedKeyEntryToDbWithTxn: "+
				"Problem deleting DerivedKeyEntry %v from db", *derivedKeyEntry)
		}

		if derivedKeyEntry.isDeleted {
			// Since entry is deleted, there's nothing to do.
			numDeleted++
		} else {
			// In this case we add the mapping to the DB.
			if err := DBPutDerivedKeyMappingWithTxn(txn, bav.Snapshot, blockHeight, derivedKeyMapKey.OwnerPublicKey, derivedKeyMapKey.DerivedPublicKey, derivedKeyEntry, bav.EventManager); err != nil {

				return errors.Wrapf(err, "UtxoView._flushDerivedKeyEntryToDbWithTxn: "+
					"Problem putting DerivedKeyEntry %v to db", *derivedKeyEntry)
			}
			numPut++
		}
	}
	glog.V(2).Infof("_flushDerivedKeyEntryToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	return nil
}

func (bav *UtxoView) _flushMessagingGroupEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushMessagingGroupEntriesToDbWithTxn: flushing %d mappings", len(bav.MessagingGroupKeyToMessagingGroupEntry))
	numDeleted := 0
	numPut := 0

	// Go through all entries in MessagingGroupKeyToMessagingGroupEntry and add them to the DB.
	// These records are part of the DeSo V3 Messages.
	for messagingGroupKey, messagingGroupEntry := range bav.MessagingGroupKeyToMessagingGroupEntry {
		// Delete the existing mapping in the DB for this map key, this will be re-added
		// later if isDeleted=false. Messaging entries can have a list of members, and
		// we store these members under a separate prefix. To delete a messaging group
		// we also have to go delete all of the recipients.
		//
		// TODO: We should have a single DeleteMappings function in db_utils.go that we push this
		// complexity into.
		existingMessagingGroupEntry := DBGetMessagingGroupEntryWithTxn(txn, bav.Snapshot, &messagingGroupKey)
		if existingMessagingGroupEntry != nil {
			if err := DBDeleteMessagingGroupEntryWithTxn(txn, bav.Snapshot, &messagingGroupKey, bav.EventManager, messagingGroupEntry.isDeleted); err != nil {
				return errors.Wrapf(err, "UtxoView._flushMessagingGroupEntriesToDbWithTxn: "+
					"Problem deleting MessagingGroupEntry %v from db", *messagingGroupEntry)
			}
			for _, member := range existingMessagingGroupEntry.MessagingGroupMembers {
				if err := DBDeleteMessagingGroupMemberMappingWithTxn(txn, bav.Snapshot, member, existingMessagingGroupEntry, bav.EventManager, messagingGroupEntry.isDeleted); err != nil {

					return errors.Wrapf(err, "UtxoView._flushMessagingGroupEntriesToDbWithTxn: "+
						"Problem deleting MessagingGroupEntry recipients (%v) from db", member)
				}
			}
		}

		if messagingGroupEntry.isDeleted {
			// Since entry is deleted, there's nothing to do.
			numDeleted++
		} else {
			// The entry isn't deleted so we re-add it to the DB. In particular, we add
			// all of the recipients.
			//
			// TODO: We should have a single PutMappings function in db_utils.go that we push this
			// complexity into.
			ownerPublicKey := messagingGroupKey.OwnerPublicKey
			if err := DBPutMessagingGroupEntryWithTxn(txn, bav.Snapshot, blockHeight, &ownerPublicKey, messagingGroupEntry, bav.EventManager); err != nil {
				return errors.Wrapf(err, "UtxoView._flushMessagingGroupEntriesToDbWithTxn: "+
					"Problem putting MessagingGroupEntry %v to db", *messagingGroupEntry)
			}
			for _, recipient := range messagingGroupEntry.MessagingGroupMembers {
				// Group owner can be one of the recipients, particularly when we want to add the
				// encrypted key addressed to the owner. This could happen when the group is created
				// by a derived key, and we want to allow the main owner key to be able to read the chat.
				if reflect.DeepEqual(recipient.GroupMemberPublicKey[:], ownerPublicKey[:]) {
					continue
				}
				if err := DBPutMessagingGroupMemberWithTxn(txn, bav.Snapshot, blockHeight, recipient, &ownerPublicKey, messagingGroupEntry, bav.EventManager); err != nil {
					return errors.Wrapf(err, "UtxoView._flushMessagingGroupEntriesToDbWithTxn: "+
						"Problem putting MessagingGroupEntry recipient (%v) to db", recipient)
				}
			}
			numPut++
		}
	}

	glog.V(2).Infof("_flushMessagingGroupEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)
	return nil
}

func (bav *UtxoView) _flushAccessGroupEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushAccessGroupEntriesToDbWithTxn: flushing %d mappings", len(bav.AccessGroupIdToAccessGroupEntry))
	numDeleted := 0
	numPut := 0

	// Go through all entries in AccessGroupIdToAccessGroupEntry and add them to the DB.
	for accessGroupKeyIter, accessGroupEntryIter := range bav.AccessGroupIdToAccessGroupEntry {
		// Delete the existing mapping in the DB for this map key, this will be re-added
		// later if isDeleted=false. Access group entries can have a list of members, and
		// we store these members under a separate prefix. To delete an access group
		// we also have to go delete all of the recipients.
		accessGroupKey := accessGroupKeyIter
		if accessGroupEntryIter == nil {
			return fmt.Errorf("UtxoView._flushAccessGroupEntriesToDbWithTxn: accessGroupEntryIter is nil")
		}
		accessGroupEntry := *accessGroupEntryIter

		if err := DBDeleteAccessGroupEntryWithTxn(txn, bav.Snapshot, accessGroupKey.AccessGroupOwnerPublicKey, accessGroupKey.AccessGroupKeyName, bav.EventManager, accessGroupEntry.isDeleted); err != nil {

			return errors.Wrapf(err, "UtxoView._flushAccessGroupEntriesToDbWithTxn: "+
				"Problem deleting accessGroupKey %v and accessGroupEntry %v from db",
				accessGroupKey, accessGroupEntry)
		}

		if accessGroupEntry.isDeleted {
			numDeleted++
		} else {
			if err := DBPutAccessGroupEntryWithTxn(txn, bav.Snapshot, blockHeight, &accessGroupEntry, bav.EventManager); err != nil {

				return errors.Wrapf(err, "UtxoView._flushAccessGroupEntriesToDbWithTxn: "+
					"Problem putting accessGroupKey %v and accessGroupEntry %v to db",
					accessGroupKey, accessGroupEntry)
			}
			numPut++
		}
	}
	glog.V(2).Infof("_flushAccessGroupEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)
	return nil
}

func (bav *UtxoView) _flushAccessGroupMembersToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushAccessGroupMembersToDbWithTxn: flushing %d mappings", len(bav.AccessGroupMembershipKeyToAccessGroupMember))
	numDeleted := 0
	numPut := 0

	// Go through all entries in AccessGroupMembershipKeyToAccessGroupMember and add them to the DB.
	for groupMembershipKeyIter, accessGroupMemberIter := range bav.AccessGroupMembershipKeyToAccessGroupMember {
		// Delete the existing mapping in the DB for this map key, this will be re-added
		// later if isDeleted=false.
		groupMembershipKey := groupMembershipKeyIter
		if accessGroupMemberIter == nil {
			return fmt.Errorf("UtxoView._flushAccessGroupMembersToDbWithTxn:"+
				" groupMembershipKey: %v, is nil", groupMembershipKey)
		}
		accessGroupMember := *accessGroupMemberIter

		// For each group member, we store two entries in the DB. One is the mapping from
		//	<AccessGroupMemberPublicKey, AccessGroupOwnerPublicKey, AccessGroupKeyName> -> <AccessGroupMemberEntry>
		// that is used to store data for all the access groups where the public key AccessGroupMemberPublicKey was added as a member.
		// The other mapping is from
		// 	<AccessGroupOwnerPublicKey, AccessGroupKeyName, AccessGroupMemberPublicKey> -> <AccessGroupMemberEnumerationEntry>
		// that is used to index the list of members for a given access group. This mapping doesn't store information about
		// the member entry, just the existence of the member. The reason we store both mappings is that we want to be able
		// to quickly iterate over all the members of a given access group, and we want to be able to quickly iterate over
		// all the access groups where a given public key is a member.
		//
		// TODO: Would probably be a bit cleaner to have one function that bundles these functions like
		// we do for other parts of the code but OK for now.
		if err := DBDeleteAccessGroupMemberEntryWithTxn(txn, bav.Snapshot, groupMembershipKey.AccessGroupMemberPublicKey, groupMembershipKey.AccessGroupOwnerPublicKey, groupMembershipKey.AccessGroupKeyName, bav.EventManager, accessGroupMember.isDeleted); err != nil {
			return errors.Wrapf(err, "UtxoView._flushAccessGroupMembersToDbWithTxn: "+
				"Fail while putting new membership index. Problem putting access group member entry with "+
				"AccessGroupMembershipKey %v and AccessGroupMemberEntry %v to db",
				groupMembershipKey, accessGroupMember)
		}
		if err := DBDeleteAccessGroupMemberEnumerationIndexWithTxn(txn, bav.Snapshot, groupMembershipKey.AccessGroupOwnerPublicKey, groupMembershipKey.AccessGroupKeyName, groupMembershipKey.AccessGroupMemberPublicKey, bav.EventManager, accessGroupMember.isDeleted); err != nil {

			return errors.Wrapf(err, "UtxoView._flushAccessGroupMembersToDbWithTxn: "+
				"Fail while putting new membership index. Problem putting access group member entry with "+
				"AccessGroupMembershipKey %v and AccessGroupMember %v to db",
				groupMembershipKey, accessGroupMember)
		}

		// add group member to enumeration index
		if accessGroupMember.isDeleted {
			numDeleted++
		} else {
			// TODO: Would probably be a bit cleaner to have one function that bundles these functions like
			// we do for other parts of the code but OK for now.
			if err := DBPutAccessGroupMemberEntryWithTxn(txn, bav.Snapshot, blockHeight, &accessGroupMember, groupMembershipKey.AccessGroupOwnerPublicKey, groupMembershipKey.AccessGroupKeyName, bav.EventManager); err != nil {

				return errors.Wrapf(err, "UtxoView._flushAccessGroupMembersToDbWithTxn: "+
					"Fail while putting new membership index. Problem putting access group member entry with "+
					"AccessGroupMembershipKey %v and AccessGroupMemberEntry %v to db",
					groupMembershipKey, accessGroupMember)
			}
			if err := DBPutAccessGroupMemberEnumerationIndexWithTxn(txn, bav.Snapshot, blockHeight, groupMembershipKey.AccessGroupOwnerPublicKey, groupMembershipKey.AccessGroupKeyName, groupMembershipKey.AccessGroupMemberPublicKey, bav.EventManager); err != nil {
				return errors.Wrapf(err, "UtxoView._flushAccessGroupMembersToDbWithTxn: "+
					"Fail while putting new enumeration index. Problem putting access group member entry with "+
					"AccessGroupMembershipKey %v and AccessGroupMemberEntry %v to db",
					groupMembershipKey, accessGroupMember)
			}
			numPut++
		}
	}
	glog.V(2).Infof("_flushAccessGroupMembersToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)
	return nil
}

func (bav *UtxoView) _flushNewMessageEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushNewMessageEntriesToDbWithTxn: flushing (len=%d) group chat messages, "+
		"(len=%d) dm messages, (len=%d) dm threads",
		len(bav.GroupChatMessagesIndex), len(bav.DmMessagesIndex), len(bav.DmThreadIndex))

	// Flush group chat messages to db.
	// Go through all entries in GroupChatMessagesIndex and add them to the DB.
	{
		numDeleted := 0
		numPut := 0
		for groupChatMessageKeyIter, messageEntryIter := range bav.GroupChatMessagesIndex {
			groupChatMessageKey := groupChatMessageKeyIter
			if messageEntryIter == nil {
				return fmt.Errorf("UtxoView._flushNewMessageEntriesToDbWithTxn: "+
					"groupChatMessageKey: %v, is nil", groupChatMessageKey)
			}
			messageEntry := *messageEntryIter

			// Delete the existing mapping in the DB for this map key, this will be re-added
			// later if isDeleted=false.
			if err := DBDeleteGroupChatMessageEntryWithTxn(txn, bav.Snapshot, groupChatMessageKey, bav.EventManager, messageEntry.isDeleted); err != nil {
				return errors.Wrapf(
					err, "_flushNewMessageEntriesToDbWithTxn: Problem deleting mappings "+
						"for GroupChatMessageKey: %v: ", &groupChatMessageKey)
			}

			if messageEntry.isDeleted {
				numDeleted++
			} else {
				if err := DBPutGroupChatMessageEntryWithTxn(txn, bav.Snapshot, blockHeight, groupChatMessageKey, &messageEntry, bav.EventManager); err != nil {
					return errors.Wrapf(
						err, "_flushNewMessageEntriesToDbWithTxn: Problem setting message entry into "+
							"group chat message index with key %v and value %v", groupChatMessageKey, messageEntry)
				}
				numPut++
			}
		}
		glog.V(2).Infof("_flushNewMessageEntriesToDbWithTxn: deleted %d group chat messages, put %d group chat messages", numDeleted, numPut)
	}

	// Flush dm messages to db.
	// Go through all entries in DmMessagesIndex and add them to the DB.
	{
		numDeleted := 0
		numPut := 0
		for dmMessageKeyIter, messageEntryIter := range bav.DmMessagesIndex {
			dmMessageKey := dmMessageKeyIter
			if messageEntryIter == nil {
				return fmt.Errorf("UtxoView._flushNewMessageEntriesToDbWithTxn: "+
					"dmMessageKey: %v, is nil", dmMessageKey)
			}
			messageEntry := *messageEntryIter

			// Delete the existing mapping in the DB for this map key, this will be re-added
			// later if isDeleted=false.
			if err := DBDeleteDmMessageEntryWithTxn(txn, bav.Snapshot, dmMessageKey, bav.EventManager, messageEntry.isDeleted); err != nil {
				return errors.Wrapf(
					err, "_flushNewMessageEntriesToDbWithTxn: Problem deleting mappings "+
						"for DmMessageKey: %v: ", &dmMessageKey)
			}

			if messageEntry.isDeleted {
				numDeleted++
			} else {
				if err := DBPutDmMessageEntryWithTxn(txn, bav.Snapshot, blockHeight, dmMessageKey, &messageEntry, bav.EventManager); err != nil {
					return errors.Wrapf(
						err, "_flushNewMessageEntriesToDbWithTxn: Problem setting message entry "+
							"into dm message index with key %v and value %v", dmMessageKey, messageEntry)
				}
				numPut++
			}
		}
		glog.V(2).Infof("_flushNewMessageEntriesToDbWithTxn: deleted %d dm messages, put %d dm messages", numDeleted, numPut)
	}

	// Flush dm threads to db.
	// Go through all entries in DmThreadIndex and add them to the DB.
	{
		numDeleted := 0
		numPut := 0
		for dmThreadKeyIter, dmThreadEntryIter := range bav.DmThreadIndex {
			dmThreadKey := dmThreadKeyIter
			if dmThreadEntryIter == nil {
				return fmt.Errorf("UtxoView._flushNewMessageEntriesToDbWithTxn: "+
					"dmThreadKey: %v, is nil", dmThreadKey)
			}
			dmThreadEntry := *dmThreadEntryIter

			// Delete the existing mapping in the DB for this map key, this will be re-added
			// later if isDeleted=false.
			if err := DBDeleteDmThreadIndexWithTxn(txn, bav.Snapshot, dmThreadKey, bav.EventManager, dmThreadEntry.isDeleted); err != nil {
				return errors.Wrapf(
					err, "_flushNewMessageEntriesToDbWithTxn: Problem deleting mappings for DmThreadKey: %v: ", &dmThreadKey)
			}

			if dmThreadEntry.isDeleted {
				numDeleted++
			} else {
				if err := DBPutDmThreadIndexWithTxn(txn, bav.Snapshot, blockHeight, dmThreadKey, bav.EventManager); err != nil {
					return errors.Wrapf(
						err, "_flushNewMessageEntriesToDbWithTxn: Problem setting DmThreadKey: %v", dmThreadKey)
				}
				numPut++
			}
		}
		glog.V(2).Infof("_flushNewMessageEntriesToDbWithTxn: deleted %d dm threads, put %d dm threads", numDeleted, numPut)
	}

	return nil
}

func (bav *UtxoView) _flushDAOCoinLimitOrderEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	glog.V(2).Infof("_flushDAOCoinLimitOrderEntriesToDbWithTxn: flushing %d mappings", len(bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry))

	// Go through all the entries in the DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry map.
	for orderIter, orderEntry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		// Make a copy of the iterator since we take references to it below.
		orderKey := orderIter

		// Validate order map key matches order entry.
		orderMapKey := orderEntry.ToMapKey()

		if !reflect.DeepEqual(orderKey, orderMapKey) {
			return fmt.Errorf("_flushDAOCoinLimitOrderEntriesToDbWithTxn: DAOCoinLimitOrderEntry has "+
				"map key: %v which does not match match "+
				"the DAOCoinLimitOrderMapKey map key %v",
				orderMapKey, orderKey)
		}

		// Delete the existing mappings in the db for this balance key. They will be re-added
		// if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteDAOCoinLimitOrderWithTxn(txn, bav.Snapshot, orderEntry, bav.EventManager, orderEntry.isDeleted); err != nil {
			return errors.Wrapf(
				err, "_flushDAOCoinLimitOrderEntriesToDbWithTxn: problem deleting mappings")
		}
	}

	// Update logs with number of entries deleted and/ put.
	numDeleted := 0
	numPut := 0

	// Go through all the entries in the DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry map.
	for _, orderEntry := range bav.DAOCoinLimitOrderMapKeyToDAOCoinLimitOrderEntry {
		// Make a copy of the iterator since we take references to it below.
		if orderEntry.isDeleted {
			numDeleted++
			// If the OrderEntry has isDeleted=true then there's nothing to do because
			// we already deleted the entry above.
		} else {
			numPut++
			// If the OrderEntry has (isDeleted = false) then we put the corresponding
			// mappings for it into the db.
			if err := DBPutDAOCoinLimitOrderWithTxn(txn, bav.Snapshot, orderEntry, blockHeight, bav.EventManager); err != nil {
				return err
			}
		}
	}

	glog.V(2).Infof("_flushDAOCoinLimitOrderEntriesToDbWithTxn: deleted %d mappings, put %d mappings", numDeleted, numPut)

	// At this point all of the DAO coin limit order mappings in the db should be up-to-date.
	return nil
}

func (bav *UtxoView) _flushUserAssociationEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Go through all the entries in the AssociationMapKeyToUserAssociationEntry map.
	for associationMapKeyIter, associationEntryIter := range bav.AssociationMapKeyToUserAssociationEntry {
		// Make a copy of the iterator since we make references to it below.
		associationMapKey := associationMapKeyIter
		associationEntry := *associationEntryIter

		// Sanity-check that the AssociationMapKey computed from the AssociationEntry
		// is equal to the AssociationMapKey that maps to that entry.
		mapKeyInEntry := associationEntry.ToMapKey()
		if mapKeyInEntry != associationMapKey {
			return fmt.Errorf(
				"_flushUserAssociationEntriesToDbWithTxn: association entry key %v doesn't match the map key %v",
				&mapKeyInEntry,
				&associationMapKey,
			)
		}

		// Delete the existing mappings in the db for this AssociationMapKey. They
		// will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DBDeleteUserAssociationWithTxn(txn, bav.Snapshot, &associationEntry, bav.EventManager, associationEntry.isDeleted); err != nil {
			return fmt.Errorf(
				"_flushUserAssociationEntriesToDbWithTxn: problem deleting association mappings for map key %v: %v",
				&associationMapKey,
				err,
			)
		}
	}

	// Go through all the entries in the AssociationMapKeyToUserAssociationEntry map.
	for _, associationEntryIter := range bav.AssociationMapKeyToUserAssociationEntry {
		associationEntry := *associationEntryIter
		if associationEntry.isDeleted {
			// If the AssociationEntry has isDeleted=true then there's
			// nothing to do because we already deleted the entry above.
		} else {
			// If the AssociationEntry has isDeleted=false then we
			// put the corresponding mappings for it into the db.
			if err := DBPutUserAssociationWithTxn(txn, bav.Snapshot, &associationEntry, blockHeight, bav.EventManager); err != nil {
				return fmt.Errorf("_flushUserAssociationEntriesToDbWithTxn: %v", err)
			}
		}
	}
	return nil
}

func (bav *UtxoView) _flushPostAssociationEntriesToDbWithTxn(txn *badger.Txn, blockHeight uint64) error {
	// Go through all the entries in the AssociationMapKeyToPostAssociationEntry map.
	for associationMapKeyIter, associationEntryIter := range bav.AssociationMapKeyToPostAssociationEntry {
		// Make a copy of the iterator since we make references to it below.
		associationMapKey := associationMapKeyIter
		associationEntry := *associationEntryIter

		// Sanity-check that the AssociationMapKey computed from the AssociationEntry
		// is equal to the AssociationMapKey that maps to that entry.
		mapKeyInEntry := associationEntry.ToMapKey()
		if mapKeyInEntry != associationMapKey {
			return fmt.Errorf(
				"_flushPostAssociationEntriesToDbWithTxn: association entry key %v doesn't match the map key %v",
				&mapKeyInEntry,
				&associationMapKey,
			)
		}

		// Delete the existing mappings in the db for this AssociationMapKey. They
		// will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DBDeletePostAssociationWithTxn(txn, bav.Snapshot, &associationEntry, bav.EventManager, associationEntry.isDeleted); err != nil {
			return fmt.Errorf(
				"_flushPostAssociationEntriesToDbWithTxn: problem deleting association mappings for map key %v: %v",
				&associationMapKey,
				err,
			)
		}
	}

	// Go through all the entries in the AssociationMapKeyToPostAssociationEntry map.
	for _, associationEntryIter := range bav.AssociationMapKeyToPostAssociationEntry {
		associationEntry := *associationEntryIter
		if associationEntry.isDeleted {
			// If the AssociationEntry has isDeleted=true then there's
			// nothing to do because we already deleted the entry above.
		} else {
			// If the AssociationEntry has isDeleted=false then we
			// put the corresponding mappings for it into the db.
			if err := DBPutPostAssociationWithTxn(txn, bav.Snapshot, &associationEntry, blockHeight, bav.EventManager); err != nil {
				return fmt.Errorf("_flushPostAssociationEntriesToDbWithTxn: %v", err)
			}
		}
	}
	return nil
}

func (bav *UtxoView) _flushNonceEntriesToDbWithTxn(txn *badger.Txn) error {
	for _, nonceEntry := range bav.TransactorNonceMapKeyToTransactorNonceEntry {
		// Delete the existing mappings in the db for this TransactorNonceEntry. They
		// will be re-added if the corresponding entry in memory has isDeleted=false.
		if err := DbDeleteTransactorNonceEntryWithTxn(txn, bav.Snapshot, nonceEntry.Nonce, nonceEntry.TransactorPKID, bav.EventManager, nonceEntry.isDeleted); err != nil {
			return fmt.Errorf(
				"_flushNonceEntriesToDbWithTxn: problem deleting account nonce mappings for account nonce %v: %v",
				nonceEntry.Nonce.String(),
				err,
			)
		}
	}

	for _, nonceEntry := range bav.TransactorNonceMapKeyToTransactorNonceEntry {
		if nonceEntry.isDeleted {
			// If the TransactorNonceEntry has isDeleted=true then there's
			// nothing to do because we already deleted the entry above.
		} else {
			// If the TransactorNonceEntry has isDeleted=false then we
			// put the corresponding mappings for it into the db.
			if err := DbPutTransactorNonceEntryWithTxn(txn, bav.Snapshot, nonceEntry.Nonce, nonceEntry.TransactorPKID, bav.EventManager); err != nil {
				return fmt.Errorf("_flushNonceEntriesToDbWithTxn: %v", err)
			}
		}
	}
	return nil
}
