package lib

import (
	"github.com/golang/glog"
	"reflect"
)

func (bav *UtxoView) _getBalanceEntryForHODLerPKIDAndCreatorPKID(
	hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) *BalanceEntry {

	// If an entry exists in the in-memory map, return the value of that mapping.
	balanceEntryKey := MakeBalanceEntryKey(hodlerPKID, creatorPKID)
	if mapValue, existsMapValue := bav.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin)[balanceEntryKey]; existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var balanceEntry *BalanceEntry
	if bav.Postgres != nil {
		balanceEntry = bav.GetBalanceEntry(hodlerPKID, creatorPKID, isDAOCoin)
	} else {
		balanceEntry = DBGetBalanceEntryForHODLerAndCreatorPKIDs(bav.Handle, hodlerPKID, creatorPKID, isDAOCoin)
	}
	if balanceEntry != nil {
		bav._setBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID, creatorPKID, isDAOCoin)
	}
	return balanceEntry
}

func (bav *UtxoView) GetBalanceEntryForHODLerPubKeyAndCreatorPubKey(
	hodlerPubKey []byte, creatorPubKey []byte, isDAOCoin bool) (
	_balanceEntry *BalanceEntry, _hodlerPKID *PKID, _creatorPKID *PKID) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPubKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPubKey)

	return bav._getBalanceEntryForHODLerPKIDAndCreatorPKID(hodlerPKID.PKID, creatorPKID.PKID, isDAOCoin), hodlerPKID.PKID, creatorPKID.PKID
}

func (bav *UtxoView) _setBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) {

	// This function shouldn't be called with nil.
	if balanceEntry == nil {
		glog.Errorf("_setBalanceEntryMappings: Called with nil BalanceEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the BalancEntry.
	balanceEntryKey := MakeBalanceEntryKey(hodlerPKID, creatorPKID)
	if isDAOCoin {
		bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry[balanceEntryKey] = balanceEntry
	} else {
		bav.HODLerPKIDCreatorPKIDToBalanceEntry[balanceEntryKey] = balanceEntry
	}
}

func (bav *UtxoView) _setBalanceEntryMappings(balanceEntry *BalanceEntry, isDAOCoin bool) {
	bav._setBalanceEntryMappingsWithPKIDs(balanceEntry, balanceEntry.HODLerPKID, balanceEntry.CreatorPKID, isDAOCoin)
}

func (bav *UtxoView) _deleteBalanceEntryMappingsWithPKIDs(
	balanceEntry *BalanceEntry, hodlerPKID *PKID, creatorPKID *PKID, isDAOCoin bool) {

	// Create a tombstone entry.
	tombstoneBalanceEntry := *balanceEntry
	tombstoneBalanceEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setBalanceEntryMappingsWithPKIDs(&tombstoneBalanceEntry, hodlerPKID, creatorPKID, isDAOCoin)
}

func (bav *UtxoView) _deleteBalanceEntryMappings(
	balanceEntry *BalanceEntry, hodlerPublicKey []byte, creatorPublicKey []byte, isDAOCoin bool) {

	// These are guaranteed to be non-nil as long as the public keys are valid.
	hodlerPKID := bav.GetPKIDForPublicKey(hodlerPublicKey)
	creatorPKID := bav.GetPKIDForPublicKey(creatorPublicKey)

	// Set the mappings to point to the tombstone entry.
	bav._deleteBalanceEntryMappingsWithPKIDs(balanceEntry, hodlerPKID.PKID, creatorPKID.PKID, isDAOCoin)
}

func (bav *UtxoView) GetHoldings(pkid *PKID, fetchProfiles bool, isDAOCoin bool) (
	[]*BalanceEntry, []*ProfileEntry, error) {
	var entriesYouHold []*BalanceEntry
	if bav.Postgres != nil {
		entriesYouHold = bav.GetBalanceEntryHoldings(pkid, isDAOCoin)
	} else {
		holdings, err := DbGetBalanceEntriesYouHold(bav.Handle, pkid, true, isDAOCoin)
		if err != nil {
			return nil, nil, err
		}
		entriesYouHold = holdings
	}

	holdingsMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range entriesYouHold {
		holdingsMap[*balanceEntry.CreatorPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin) {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdingsMap[*balanceEntry.CreatorPKID]; ok {
				// We found both a mempool and a db balanceEntry. Update the BalanceEntry using mempool data.
				holdingsMap[*balanceEntry.CreatorPKID].BalanceNanos = balanceEntry.BalanceNanos
			} else {
				// Add new entries to the list
				entriesYouHold = append(entriesYouHold, balanceEntry)
			}
		}
	}

	// Optionally fetch all the profile entries as well.
	var profilesYouHold []*ProfileEntry
	if fetchProfiles {
		for _, balanceEntry := range entriesYouHold {
			// In this case you're the hodler so the creator is the one whose profile we need to fetch.
			currentProfileEntry := bav.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			profilesYouHold = append(profilesYouHold, currentProfileEntry)
		}
	}

	return entriesYouHold, profilesYouHold, nil
}

func (bav *UtxoView) GetHolders(pkid *PKID, fetchProfiles bool, isDAOCoin bool) (
	[]*BalanceEntry, []*ProfileEntry, error) {
	var holderEntries []*BalanceEntry
	if bav.Postgres != nil {
		holderEntries = bav.GetBalanceEntryHolders(pkid, isDAOCoin)
	} else {
		holders, err := DbGetBalanceEntriesHodlingYou(bav.Handle, pkid, true, isDAOCoin)
		if err != nil {
			return nil, nil, err
		}
		holderEntries = holders
	}

	holdersMap := make(map[PKID]*BalanceEntry)
	for _, balanceEntry := range holderEntries {
		holdersMap[*balanceEntry.HODLerPKID] = balanceEntry
	}

	for _, balanceEntry := range bav.GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin) {
		if reflect.DeepEqual(balanceEntry.HODLerPKID, pkid) {
			if _, ok := holdersMap[*balanceEntry.HODLerPKID]; ok {
				// We found both a mempool and a db balanceEntry. Update the BalanceEntry using mempool data.
				holdersMap[*balanceEntry.HODLerPKID].BalanceNanos = balanceEntry.BalanceNanos
			} else {
				// Add new entries to the list
				holderEntries = append(holderEntries, balanceEntry)
			}
		}
	}

	// Optionally fetch all the profile entries as well.
	var profilesYouHold []*ProfileEntry
	if fetchProfiles {
		for _, balanceEntry := range holderEntries {
			// In this case you're the hodler so the creator is the one whose profile we need to fetch.
			currentProfileEntry := bav.GetProfileEntryForPKID(balanceEntry.CreatorPKID)
			profilesYouHold = append(profilesYouHold, currentProfileEntry)
		}
	}

	return holderEntries, profilesYouHold, nil
}

func (bav *UtxoView) GetHODLerPKIDCreatorPKIDToBalanceEntryMap(isDAOCoin bool) map[BalanceEntryMapKey]*BalanceEntry {
	if isDAOCoin {
		return bav.HODLerPKIDCreatorPKIDToDAOCoinBalanceEntry
	} else {
		return bav.HODLerPKIDCreatorPKIDToBalanceEntry
	}
}

//
// BalanceEntry Postgres
//

func (bav *UtxoView) GetBalanceEntry(holderPkid *PKID, creatorPkid *PKID, isDAOCoin bool) *BalanceEntry {
	if bav.Postgres == nil {
		return nil
	}
	var balanceEntry *BalanceEntry
	if isDAOCoin {
		balance := bav.Postgres.GetDAOCoinBalance(holderPkid, creatorPkid)
		if balance != nil {
			balanceEntry = balance.NewBalanceEntry()
		}
	} else {
		balance := bav.Postgres.GetCreatorCoinBalance(holderPkid, creatorPkid)
		if balance != nil {
			balanceEntry = balance.NewBalanceEntry()
		}
	}
	return balanceEntry
}

func (bav *UtxoView) GetBalanceEntryHoldings(pkid *PKID, isDAOCoin bool) []*BalanceEntry {
	if bav.Postgres == nil {
		return nil
	}
	var balanceEntries []*BalanceEntry
	if isDAOCoin {
		balances := bav.Postgres.GetDAOCoinHoldings(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	} else {
		balances := bav.Postgres.GetCreatorCoinHoldings(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	}
	return balanceEntries
}

func (bav *UtxoView) GetBalanceEntryHolders(pkid *PKID, isDAOCoin bool) []*BalanceEntry {
	if bav.Postgres == nil {
		return nil
	}
	var balanceEntries []*BalanceEntry
	if isDAOCoin {
		balances := bav.Postgres.GetDAOCoinHolders(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	} else {
		balances := bav.Postgres.GetCreatorCoinHolders(pkid)
		for _, balance := range balances {
			balanceEntries = append(balanceEntries, balance.NewBalanceEntry())
		}
	}
	return balanceEntries
}
