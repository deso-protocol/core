package lib

import (
	"github.com/golang/glog"
	"reflect"
)

func (bav *UtxoView) _setNFTEntryMappings(nftEntry *NFTEntry) {
	// This function shouldn't be called with nil.
	if nftEntry == nil {
		glog.Errorf("_setNFTEntryMappings: Called with nil NFTEntry; " +
			"this should never happen.")
		return
	}

	nftKey := MakeNFTKey(nftEntry.NFTPostHash, nftEntry.SerialNumber)
	bav.NFTKeyToNFTEntry[nftKey] = nftEntry
}

func (bav *UtxoView) _deleteNFTEntryMappings(nftEntry *NFTEntry) {

	// Create a tombstone entry.
	tombstoneNFTEntry := *nftEntry
	tombstoneNFTEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setNFTEntryMappings(&tombstoneNFTEntry)
}

func (bav *UtxoView) GetNFTEntryForNFTKey(nftKey *NFTKey) *NFTEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.NFTKeyToNFTEntry[*nftKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var nftEntry *NFTEntry
	if bav.Postgres != nil {
		nft := bav.Postgres.GetNFT(&nftKey.NFTPostHash, nftKey.SerialNumber)
		if nft != nil {
			nftEntry = nft.NewNFTEntry()
		}
	} else {
		nftEntry = DBGetNFTEntryByPostHashSerialNumber(bav.Handle, &nftKey.NFTPostHash, nftKey.SerialNumber)
	}

	if nftEntry != nil {
		bav._setNFTEntryMappings(nftEntry)
	}
	return nftEntry
}

func (bav *UtxoView) GetNFTEntriesForPostHash(nftPostHash *BlockHash) []*NFTEntry {
	// Get all the entries in the DB.
	var dbNFTEntries []*NFTEntry
	if bav.Postgres != nil {
		nfts := bav.Postgres.GetNFTsForPostHash(nftPostHash)
		for _, nft := range nfts {
			dbNFTEntries = append(dbNFTEntries, nft.NewNFTEntry())
		}
	} else {
		dbNFTEntries = DBGetNFTEntriesForPostHash(bav.Handle, nftPostHash)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbNFTEntry := range dbNFTEntries {
		nftKey := MakeNFTKey(dbNFTEntry.NFTPostHash, dbNFTEntry.SerialNumber)

		// If the NFT is not in the view, add it to the view.
		if _, ok := bav.NFTKeyToNFTEntry[nftKey]; !ok {
			bav._setNFTEntryMappings(dbNFTEntry)
		}
	}

	// Loop over the view and build the final set of NFTEntries to return.
	nftEntries := []*NFTEntry{}
	for _, nftEntry := range bav.NFTKeyToNFTEntry {
		if !nftEntry.isDeleted && reflect.DeepEqual(nftEntry.NFTPostHash, nftPostHash) {
			nftEntries = append(nftEntries, nftEntry)
		}
	}
	return nftEntries
}

func (bav *UtxoView) GetNFTEntriesForPKID(ownerPKID *PKID) []*NFTEntry {
	var dbNFTEntries []*NFTEntry
	if bav.Postgres != nil {
		nfts := bav.Postgres.GetNFTsForPKID(ownerPKID)
		for _, nft := range nfts {
			dbNFTEntries = append(dbNFTEntries, nft.NewNFTEntry())
		}
	} else {
		dbNFTEntries = DBGetNFTEntriesForPKID(bav.Handle, ownerPKID)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbNFTEntry := range dbNFTEntries {
		nftKey := MakeNFTKey(dbNFTEntry.NFTPostHash, dbNFTEntry.SerialNumber)

		// If the NFT is not in the view, add it to the view.
		if _, ok := bav.NFTKeyToNFTEntry[nftKey]; !ok {
			bav._setNFTEntryMappings(dbNFTEntry)
		}
	}

	// Loop over the view and build the final set of NFTEntries to return.
	nftEntries := []*NFTEntry{}
	for _, nftEntry := range bav.NFTKeyToNFTEntry {
		if !nftEntry.isDeleted && reflect.DeepEqual(nftEntry.OwnerPKID, ownerPKID) {
			nftEntries = append(nftEntries, nftEntry)
		}
	}
	return nftEntries
}

func (bav *UtxoView) GetNFTBidEntriesForPKID(bidderPKID *PKID) (_nftBidEntries []*NFTBidEntry) {
	var dbNFTBidEntries []*NFTBidEntry
	if bav.Postgres != nil {
		bids := bav.Postgres.GetNFTBidsForPKID(bidderPKID)
		for _, bid := range bids {
			dbNFTBidEntries = append(dbNFTBidEntries, bid.NewNFTBidEntry())
		}
	} else {
		dbNFTBidEntries = DBGetNFTBidEntriesForPKID(bav.Handle, bidderPKID)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbNFTBidEntry := range dbNFTBidEntries {
		nftBidKey := MakeNFTBidKey(bidderPKID, dbNFTBidEntry.NFTPostHash, dbNFTBidEntry.SerialNumber)

		// If the NFT is not in the view, add it to the view.
		if _, ok := bav.NFTBidKeyToNFTBidEntry[nftBidKey]; !ok {
			bav._setNFTBidEntryMappings(dbNFTBidEntry)
		}
	}

	// Loop over the view and build the final set of NFTEntries to return.
	nftBidEntries := []*NFTBidEntry{}
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if !nftBidEntry.isDeleted && reflect.DeepEqual(nftBidEntry.BidderPKID, bidderPKID) {
			nftBidEntries = append(nftBidEntries, nftBidEntry)
		}
	}
	return nftBidEntries
}

// TODO: Postgres
func (bav *UtxoView) GetHighAndLowBidsForNFTCollection(
	nftHash *BlockHash,
) (_highBid uint64, _lowBid uint64) {
	highBid := uint64(0)
	lowBid := uint64(0)
	postEntry := bav.GetPostEntryForPostHash(nftHash)

	// First we get the highest and lowest bids from the db.
	for ii := uint64(1); ii <= postEntry.NumNFTCopies; ii++ {
		highBidForSerialNum, lowBidForSerialNum := bav.GetDBHighAndLowBidsForNFT(nftHash, ii)

		if highBidForSerialNum > highBid {
			highBid = highBidForSerialNum
		}

		if lowBidForSerialNum < lowBid {
			lowBid = lowBidForSerialNum
		}
	}

	// Then we loop over the view to for anything we missed.
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if !nftBidEntry.isDeleted && reflect.DeepEqual(nftBidEntry.NFTPostHash, nftHash) {
			if nftBidEntry.BidAmountNanos > highBid {
				highBid = nftBidEntry.BidAmountNanos
			}

			if nftBidEntry.BidAmountNanos < lowBid {
				lowBid = nftBidEntry.BidAmountNanos
			}
		}
	}

	return highBid, lowBid
}

// TODO: Postgres
func (bav *UtxoView) GetHighAndLowBidsForNFTSerialNumber(nftHash *BlockHash, serialNumber uint64) (_highBid uint64, _lowBid uint64) {
	highBid := uint64(0)
	lowBid := uint64(0)

	highBidEntry, lowBidEntry := bav.GetDBHighAndLowBidEntriesForNFT(nftHash, serialNumber)

	if highBidEntry != nil {
		highBidKey := MakeNFTBidKey(highBidEntry.BidderPKID, highBidEntry.NFTPostHash, highBidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[highBidKey]; !exists {
			bav._setNFTBidEntryMappings(highBidEntry)
		}
		highBid = highBidEntry.BidAmountNanos
	}

	if lowBidEntry != nil {
		lowBidKey := MakeNFTBidKey(lowBidEntry.BidderPKID, lowBidEntry.NFTPostHash, lowBidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[lowBidKey]; !exists {
			bav._setNFTBidEntryMappings(lowBidEntry)
		}
		lowBid = lowBidEntry.BidAmountNanos
	}

	// Then we loop over the view to for anything we missed.
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {
		if !nftBidEntry.isDeleted && nftBidEntry.SerialNumber == serialNumber && reflect.DeepEqual(nftBidEntry.NFTPostHash, nftHash) {
			if nftBidEntry.BidAmountNanos > highBid {
				highBid = nftBidEntry.BidAmountNanos
			}

			if nftBidEntry.BidAmountNanos < lowBid {
				lowBid = nftBidEntry.BidAmountNanos
			}
		}
	}
	return highBid, lowBid
}

// TODO: Postgres
func (bav *UtxoView) GetDBHighAndLowBidsForNFT(nftHash *BlockHash, serialNumber uint64) (_highBid uint64, _lowBid uint64) {
	highBidAmount := uint64(0)
	lowBidAmount := uint64(0)
	highBidEntry, lowBidEntry := bav.GetDBHighAndLowBidEntriesForNFT(nftHash, serialNumber)
	if highBidEntry != nil {
		highBidAmount = highBidEntry.BidAmountNanos
	}
	if lowBidEntry != nil {
		lowBidAmount = lowBidEntry.BidAmountNanos
	}
	return highBidAmount, lowBidAmount
}

// This function gets the highest and lowest bids for a specific NFT that
// have not been deleted in the view.
// TODO: Postgres
func (bav *UtxoView) GetDBHighAndLowBidEntriesForNFT(
	nftHash *BlockHash, serialNumber uint64,
) (_highBidEntry *NFTBidEntry, _lowBidEntry *NFTBidEntry) {
	numPerDBFetch := 5
	var highestBidEntry *NFTBidEntry
	var lowestBidEntry *NFTBidEntry

	// Loop until we find the highest bid in the database that hasn't been deleted in the view.
	exitLoop := false
	highBidEntries := DBGetNFTBidEntriesPaginated(
		bav.Handle, nftHash, serialNumber, nil, numPerDBFetch, true)
	for _, bidEntry := range highBidEntries {
		bidEntryKey := MakeNFTBidKey(bidEntry.BidderPKID, bidEntry.NFTPostHash, bidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[bidEntryKey]; !exists {
			bav._setNFTBidEntryMappings(bidEntry)
		}
	}
	for {
		for _, highBidEntry := range highBidEntries {
			bidKey := &NFTBidKey{
				NFTPostHash:  *highBidEntry.NFTPostHash,
				SerialNumber: highBidEntry.SerialNumber,
				BidderPKID:   *highBidEntry.BidderPKID,
			}
			bidEntry := bav.NFTBidKeyToNFTBidEntry[*bidKey]
			if !bidEntry.isDeleted && !exitLoop {
				exitLoop = true
				highestBidEntry = bidEntry
			}
		}

		if len(highBidEntries) < numPerDBFetch {
			exitLoop = true
		}

		if exitLoop {
			break
		} else {
			nextStartEntry := highBidEntries[len(highBidEntries)-1]
			highBidEntries = DBGetNFTBidEntriesPaginated(
				bav.Handle, nftHash, serialNumber, nextStartEntry, numPerDBFetch, true,
			)
		}
	}

	// Loop until we find the lowest bid in the database that hasn't been deleted in the view.
	exitLoop = false
	lowBidEntries := DBGetNFTBidEntriesPaginated(
		bav.Handle, nftHash, serialNumber, nil, numPerDBFetch, false)
	for _, bidEntry := range lowBidEntries {
		bidEntryKey := MakeNFTBidKey(bidEntry.BidderPKID, bidEntry.NFTPostHash, bidEntry.SerialNumber)
		if _, exists := bav.NFTBidKeyToNFTBidEntry[bidEntryKey]; !exists {
			bav._setNFTBidEntryMappings(bidEntry)
		}
	}
	for {
		for _, lowBidEntry := range lowBidEntries {
			bidKey := &NFTBidKey{
				NFTPostHash:  *lowBidEntry.NFTPostHash,
				SerialNumber: lowBidEntry.SerialNumber,
				BidderPKID:   *lowBidEntry.BidderPKID,
			}
			bidEntry := bav.NFTBidKeyToNFTBidEntry[*bidKey]
			if !bidEntry.isDeleted && !exitLoop {
				exitLoop = true
				lowestBidEntry = bidEntry
			}
		}

		if len(lowBidEntries) < numPerDBFetch {
			exitLoop = true
		}

		if exitLoop {
			break
		} else {
			nextStartEntry := lowBidEntries[len(lowBidEntries)-1]
			lowBidEntries = DBGetNFTBidEntriesPaginated(
				bav.Handle, nftHash, serialNumber, nextStartEntry, numPerDBFetch, false,
			)
		}
	}

	return highestBidEntry, lowestBidEntry
}

func (bav *UtxoView) _setAcceptNFTBidHistoryMappings(nftKey NFTKey, nftBidEntries *[]*NFTBidEntry) {
	if nftBidEntries == nil {
		glog.Errorf("_setAcceptedNFTBidHistoryMappings: Called with nil nftBidEntries; " +
			"this should never happen.")
		return
	}

	bav.NFTKeyToAcceptedNFTBidHistory[nftKey] = nftBidEntries
}

func (bav *UtxoView) GetAcceptNFTBidHistoryForNFTKey(nftKey *NFTKey) *[]*NFTBidEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.

	mapValue, existsMapValue := bav.NFTKeyToAcceptedNFTBidHistory[*nftKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	dbNFTBidEntries := DBGetAcceptedNFTBidEntriesByPostHashSerialNumber(bav.Handle, &nftKey.NFTPostHash, nftKey.SerialNumber)
	if dbNFTBidEntries != nil {
		bav._setAcceptNFTBidHistoryMappings(*nftKey, dbNFTBidEntries)
		return dbNFTBidEntries
	}
	// We return an empty slice instead of nil
	return &[]*NFTBidEntry{}
}

func (bav *UtxoView) _setNFTBidEntryMappings(nftBidEntry *NFTBidEntry) {
	// This function shouldn't be called with nil.
	if nftBidEntry == nil {
		glog.Errorf("_setNFTBidEntryMappings: Called with nil nftBidEntry; " +
			"this should never happen.")
		return
	}

	nftBidKey := MakeNFTBidKey(nftBidEntry.BidderPKID, nftBidEntry.NFTPostHash, nftBidEntry.SerialNumber)
	bav.NFTBidKeyToNFTBidEntry[nftBidKey] = nftBidEntry
}

func (bav *UtxoView) _deleteNFTBidEntryMappings(nftBidEntry *NFTBidEntry) {

	// Create a tombstone entry.
	tombstoneNFTBidEntry := *nftBidEntry
	tombstoneNFTBidEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setNFTBidEntryMappings(&tombstoneNFTBidEntry)
}

func (bav *UtxoView) GetNFTBidEntryForNFTBidKey(nftBidKey *NFTBidKey) *NFTBidEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.NFTBidKeyToNFTBidEntry[*nftBidKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil.
	var dbNFTBidEntry *NFTBidEntry
	if bav.Postgres != nil {
		bidEntry := bav.Postgres.GetNFTBid(&nftBidKey.NFTPostHash, &nftBidKey.BidderPKID, nftBidKey.SerialNumber)
		if bidEntry != nil {
			dbNFTBidEntry = bidEntry.NewNFTBidEntry()
		}
	} else {
		dbNFTBidEntry = DBGetNFTBidEntryForNFTBidKey(bav.Handle, nftBidKey)
	}

	if dbNFTBidEntry != nil {
		bav._setNFTBidEntryMappings(dbNFTBidEntry)
	}

	return dbNFTBidEntry
}

func (bav *UtxoView) GetAllNFTBidEntries(nftPostHash *BlockHash, serialNumber uint64) []*NFTBidEntry {
	// Get all the entries in the DB.
	var dbEntries []*NFTBidEntry
	if bav.Postgres != nil {
		bids := bav.Postgres.GetNFTBidsForSerial(nftPostHash, serialNumber)
		for _, bid := range bids {
			dbEntries = append(dbEntries, bid.NewNFTBidEntry())
		}
	} else {
		dbEntries = DBGetNFTBidEntries(bav.Handle, nftPostHash, serialNumber)
	}

	// Make sure all of the DB entries are loaded in the view.
	for _, dbEntry := range dbEntries {
		nftBidKey := MakeNFTBidKey(dbEntry.BidderPKID, dbEntry.NFTPostHash, dbEntry.SerialNumber)

		// If the bidEntry is not in the view, add it to the view.
		if _, ok := bav.NFTBidKeyToNFTBidEntry[nftBidKey]; !ok {
			bav._setNFTBidEntryMappings(dbEntry)
		}
	}

	// Loop over the view and build the final set of NFTBidEntries to return.
	nftBidEntries := []*NFTBidEntry{}
	for _, nftBidEntry := range bav.NFTBidKeyToNFTBidEntry {

		if nftBidEntry.SerialNumber == serialNumber && !nftBidEntry.isDeleted &&
			reflect.DeepEqual(nftBidEntry.NFTPostHash, nftPostHash) {

			nftBidEntries = append(nftBidEntries, nftBidEntry)
		}
	}
	return nftBidEntries
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
