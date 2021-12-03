package lib

import (
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) GetDiamondEntryForDiamondKey(diamondKey *DiamondKey) *DiamondEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	bavDiamondEntry, existsMapValue := bav.DiamondKeyToDiamondEntry[*diamondKey]
	if existsMapValue {
		return bavDiamondEntry
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var diamondEntry *DiamondEntry
	if bav.Postgres != nil {
		diamond := bav.Postgres.GetDiamond(&diamondKey.SenderPKID, &diamondKey.ReceiverPKID, &diamondKey.DiamondPostHash)
		if diamond != nil {
			diamondEntry = &DiamondEntry{
				SenderPKID:      diamond.SenderPKID,
				ReceiverPKID:    diamond.ReceiverPKID,
				DiamondPostHash: diamond.DiamondPostHash,
				DiamondLevel:    int64(diamond.DiamondLevel),
			}
		}
	} else {
		diamondEntry = DbGetDiamondMappings(bav.Handle, &diamondKey.ReceiverPKID, &diamondKey.SenderPKID, &diamondKey.DiamondPostHash)
	}

	if diamondEntry != nil {
		bav._setDiamondEntryMappings(diamondEntry)
	}

	return diamondEntry
}

func (bav *UtxoView) GetDiamondEntryMapForPublicKey(publicKey []byte, fetchYouDiamonded bool,
) (_pkidToDiamondsMap map[PKID][]*DiamondEntry, _err error) {
	pkidEntry := bav.GetPKIDForPublicKey(publicKey)

	dbPKIDToDiamondsMap, err := DbGetPKIDsThatDiamondedYouMap(bav.Handle, pkidEntry.PKID, fetchYouDiamonded)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDiamondEntryMapForPublicKey: Error Getting "+
			"PKIDs that diamonded you map from the DB.")
	}

	// Load all of the diamondEntries into the view.
	for _, diamondEntryList := range dbPKIDToDiamondsMap {
		for _, diamondEntry := range diamondEntryList {
			diamondKey := &DiamondKey{
				SenderPKID:      *diamondEntry.SenderPKID,
				ReceiverPKID:    *diamondEntry.ReceiverPKID,
				DiamondPostHash: *diamondEntry.DiamondPostHash,
			}
			// If the diamond key is not in the view, add it to the view.
			if _, ok := bav.DiamondKeyToDiamondEntry[*diamondKey]; !ok {
				bav._setDiamondEntryMappings(diamondEntry)
			}
		}
	}

	// Iterate over all the diamondEntries in the view and build the final map.
	pkidToDiamondsMap := make(map[PKID][]*DiamondEntry)
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			continue
		}
		// Make sure the diamondEntry we are looking at is for the correct receiver public key.
		if !fetchYouDiamonded && reflect.DeepEqual(diamondEntry.ReceiverPKID, pkidEntry.PKID) {
			pkidToDiamondsMap[*diamondEntry.SenderPKID] = append(
				pkidToDiamondsMap[*diamondEntry.SenderPKID], diamondEntry)
		}

		// Make sure the diamondEntry we are looking at is for the correct sender public key.
		if fetchYouDiamonded && reflect.DeepEqual(diamondEntry.SenderPKID, pkidEntry.PKID) {
			pkidToDiamondsMap[*diamondEntry.ReceiverPKID] = append(
				pkidToDiamondsMap[*diamondEntry.ReceiverPKID], diamondEntry)
		}
	}

	return pkidToDiamondsMap, nil
}

func (bav *UtxoView) GetDiamondEntriesForSenderToReceiver(receiverPublicKey []byte, senderPublicKey []byte,
) (_diamondEntries []*DiamondEntry, _err error) {

	receiverPKIDEntry := bav.GetPKIDForPublicKey(receiverPublicKey)
	senderPKIDEntry := bav.GetPKIDForPublicKey(senderPublicKey)
	dbDiamondEntries, err := DbGetDiamondEntriesForSenderToReceiver(bav.Handle, receiverPKIDEntry.PKID, senderPKIDEntry.PKID)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDiamondEntriesForGiverToReceiver: Error getting diamond entries from DB.")
	}

	// Load all of the diamondEntries into the view
	for _, diamondEntry := range dbDiamondEntries {
		diamondKey := &DiamondKey{
			SenderPKID:      *diamondEntry.SenderPKID,
			ReceiverPKID:    *diamondEntry.ReceiverPKID,
			DiamondPostHash: *diamondEntry.DiamondPostHash,
		}
		// If the diamond key is not in the view, add it to the view.
		if _, ok := bav.DiamondKeyToDiamondEntry[*diamondKey]; !ok {
			bav._setDiamondEntryMappings(diamondEntry)
		}
	}

	var diamondEntries []*DiamondEntry
	for _, diamondEntry := range bav.DiamondKeyToDiamondEntry {
		if diamondEntry.isDeleted {
			continue
		}

		// Make sure the diamondEntry we are looking at is for the correct sender and receiver pair
		if reflect.DeepEqual(diamondEntry.ReceiverPKID, receiverPKIDEntry.PKID) &&
			reflect.DeepEqual(diamondEntry.SenderPKID, senderPKIDEntry.PKID) {
			diamondEntries = append(diamondEntries, diamondEntry)
		}
	}

	return diamondEntries, nil
}

func (bav *UtxoView) _deleteDiamondEntryMappings(diamondEntry *DiamondEntry) {

	// Create a tombstone entry.
	tombstoneDiamondEntry := *diamondEntry
	tombstoneDiamondEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDiamondEntryMappings(&tombstoneDiamondEntry)
}

func (bav *UtxoView) _setDiamondEntryMappings(diamondEntry *DiamondEntry) {
	// This function shouldn't be called with nil.
	if diamondEntry == nil {
		glog.Errorf("_setDiamondEntryMappings: Called with nil DiamondEntry; " +
			"this should never happen.")
		return
	}

	diamondKey := MakeDiamondKey(
		diamondEntry.SenderPKID, diamondEntry.ReceiverPKID, diamondEntry.DiamondPostHash)
	bav.DiamondKeyToDiamondEntry[diamondKey] = diamondEntry
}
