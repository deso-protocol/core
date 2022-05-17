package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"math/big"
	"reflect"
	"sort"
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
		nftEntry = DBGetNFTEntryByPostHashSerialNumber(bav.Handle, bav.Snapshot,
			&nftKey.NFTPostHash, nftKey.SerialNumber)
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
	dbNFTBidEntries := DBGetAcceptedNFTBidEntriesByPostHashSerialNumber(
		bav.Handle, bav.Snapshot, &nftKey.NFTPostHash, nftKey.SerialNumber)
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
		dbNFTBidEntry = DBGetNFTBidEntryForNFTBidKey(bav.Handle, bav.Snapshot, nftBidKey)
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
	// Make sure NFT Bid entries are returned in a deterministic order. Bids must differ by BidderPKID, given they have
	// distinct NFTBidKeys in the NFTBidKeyToNFTBidEntry map, so we use BidderPKID to order the bid entries.
	sort.Slice(nftBidEntries, func(i int, j int) bool {
		switch bytes.Compare(nftBidEntries[i].BidderPKID.ToBytes(), nftBidEntries[j].BidderPKID.ToBytes()) {
		case 0:
			return true
		case -1:
			return true
		case 1:
			return false
		}
		return false
	})
	return nftBidEntries
}

func (bav *UtxoView) _getBuyNowExtraData(txn *MsgDeSoTxn, blockHeight uint32) (
	_isBuyNow bool, _buyNowPrice uint64, _err error) {

	isBuyNow := false
	buyNowPrice := uint64(0)

	// Only extract the BuyNowPriceKey value if we are past the BuyNowAndNFTSplitsBlockHeight
	if val, exists := txn.ExtraData[BuyNowPriceKey]; exists &&
		blockHeight >= bav.Params.ForkHeights.BuyNowAndNFTSplitsBlockHeight {
		var bytesRead int
		buyNowPrice, bytesRead = Uvarint(val)
		if bytesRead <= 0 {
			return false, 0, errors.New(
				"_getBuyNowExtraData: Problem reading bytes for BuyNowPriceNanos")
		}
		isBuyNow = true
	}

	return isBuyNow, buyNowPrice, nil
}

// Pull out a function that converts extraData to the map that we need
// for royalties.
func (bav *UtxoView) extractAdditionalRoyaltyMap(
	key string, extraData map[string][]byte, blockHeight uint32) (
	_additionalRoyaltiesMap map[PKID]uint64, _additionalRoyaltyBasisPoints uint64, _err error) {

	additionalRoyalties := make(map[PKID]uint64)
	additionalRoyaltiesBasisPoints := uint64(0)
	if mapBytes, exists := extraData[key]; exists &&
		blockHeight >= bav.Params.ForkHeights.BuyNowAndNFTSplitsBlockHeight {

		var err error
		additionalRoyaltiesByPubKey, err := DeserializePubKeyToUint64Map(mapBytes)
		if err != nil {
			return nil, 0, errors.Wrap(err,
				"Problem reading bytes for additional royalties: ")
		}
		// Check that public keys are valid and sum basis points
		for pkBytesIter, bps := range additionalRoyaltiesByPubKey {
			// Make a copy of the iterator
			pkBytess := pkBytesIter

			// Validate the public key
			if _, err = btcec.ParsePubKey(pkBytess[:], btcec.S256()); err != nil {
				return nil, 0, errors.Wrapf(
					RuleErrorAdditionalRoyaltyPubKeyMustBeValid,
					"Error parsing public key: %v, %v", PkToStringBoth(pkBytess[:]), err)
			}
			// Set the PKID on the map
			pkid := bav.GetPKIDForPublicKey(pkBytess[:])
			additionalRoyalties[*pkid.PKID] = bps

			// Check for overflow when summing the bps
			if additionalRoyaltiesBasisPoints > math.MaxUint64-bps {
				return nil, 0, errors.Wrapf(
					RuleErrorAdditionalCoinRoyaltyOverflow,
					"additionalRoyaltiesBasisPoints: %v, bps: %v", additionalRoyaltiesBasisPoints, bps)
			}
			// Add the bps to our total
			additionalRoyaltiesBasisPoints += bps

			if key == CoinRoyaltiesMapKey {
				existingProfileEntry := bav.GetProfileEntryForPublicKey(pkBytess[:])
				if existingProfileEntry == nil || existingProfileEntry.isDeleted {
					return nil, 0, errors.Wrapf(
						RuleErrorAdditionalCoinRoyaltyMustHaveProfile,
						"Profile missing for additional Coin NFT royalty pub key: %v",
						PkToStringBoth(pkBytess[:]))
				}
			}
		}
	}
	return additionalRoyalties, additionalRoyaltiesBasisPoints, nil
}

func (bav *UtxoView) _connectCreateNFT(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreateNFT {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*CreateNFTMetadata)

	isBuyNow, buyNowPrice, err := bav._getBuyNowExtraData(txn, blockHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreateNFT: ")
	}

	// Extract additional DESO royalties
	additionalDESONFTRoyalties, additionalDESONFTRoyaltiesBasisPoints, err := bav.extractAdditionalRoyaltyMap(
		DESORoyaltiesMapKey, txn.ExtraData, blockHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err,
			"_connectCreateNFT: Problem extract additional DESO Royalties: ")
	}

	// Extract additional coin royalties
	additionalCoinNFTRoyalties, additionalCoinNFTRoyaltiesBasisPoints, err := bav.extractAdditionalRoyaltyMap(
		CoinRoyaltiesMapKey, txn.ExtraData, blockHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrap(err,
			"_connectCreateNFT: Problem extract additional Coin Royalties: ")
	}

	// Validate the txMeta.
	if txMeta.NumCopies > bav.GlobalParamsEntry.MaxCopiesPerNFT {
		return 0, 0, nil, RuleErrorTooManyNFTCopies
	}
	if txMeta.NumCopies == 0 {
		return 0, 0, nil, RuleErrorNFTMustHaveNonZeroCopies
	}
	// Make sure we won't overflow when we add the royalty basis points.
	if math.MaxUint64-txMeta.NFTRoyaltyToCoinBasisPoints-additionalDESONFTRoyaltiesBasisPoints-
		additionalCoinNFTRoyaltiesBasisPoints < txMeta.NFTRoyaltyToCreatorBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyOverflow
	}
	// Make sure we won't overflow when we add the royalty basis points.
	if math.MaxUint64-txMeta.NFTRoyaltyToCreatorBasisPoints-additionalDESONFTRoyaltiesBasisPoints-
		additionalCoinNFTRoyaltiesBasisPoints < txMeta.NFTRoyaltyToCoinBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyOverflow
	}

	// Make sure we won't overflow when we add the royalty basis points.
	if math.MaxUint64-txMeta.NFTRoyaltyToCreatorBasisPoints-txMeta.NFTRoyaltyToCoinBasisPoints-
		additionalCoinNFTRoyaltiesBasisPoints < additionalDESONFTRoyaltiesBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyOverflow
	}

	// Make sure we won't overflow when we add the royalty basis points.
	if math.MaxUint64-txMeta.NFTRoyaltyToCreatorBasisPoints-txMeta.NFTRoyaltyToCoinBasisPoints-
		additionalDESONFTRoyaltiesBasisPoints < additionalCoinNFTRoyaltiesBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyOverflow
	}

	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, RuleErrorCreateNFTOnNonexistentPost
	}

	posterPKID := bav.GetPKIDForPublicKey(postEntry.PosterPublicKey)
	if posterPKID == nil || posterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: non-existent posterPKID: %s",
			PkToString(postEntry.PosterPublicKey, bav.Params))
	}

	if IsVanillaRepost(postEntry) {
		return 0, 0, nil, RuleErrorCreateNFTOnVanillaRepost
	}
	if !reflect.DeepEqual(postEntry.PosterPublicKey, txn.PublicKey) {
		return 0, 0, nil, RuleErrorCreateNFTMustBeCalledByPoster
	}
	if postEntry.IsNFT {
		return 0, 0, nil, RuleErrorCreateNFTOnPostThatAlreadyIsNFT
	}
	// We can't encrypt unlockable content if Buy Now is enabled.
	if txMeta.HasUnlockable && isBuyNow {
		return 0, 0, nil, errors.Wrapf(RuleErrorCannotHaveUnlockableAndBuyNowNFT, "_connectCreateNFT: ")
	}
	// We can't have a Buy Now NFT with a buy now price below min bid amount
	if isBuyNow && txMeta.MinBidAmountNanos > buyNowPrice {
		return 0, 0, nil, errors.Wrapf(RuleErrorCannotHaveBuyNowPriceBelowMinBidAmountNanos, "_connectCreateNFT: ")
	}

	// Make sure the creator of the post is not specified in the royalties maps
	if _, exists := additionalDESONFTRoyalties[*posterPKID.PKID]; exists {
		return 0, 0, nil, errors.Wrapf(RuleErrorCannotSpecifyCreatorAsAdditionalRoyalty,
			"_connectCreateNFT: cannot specify the post creator in the additional DESO royalties map")
	}

	if _, exists := additionalCoinNFTRoyalties[*posterPKID.PKID]; exists {
		return 0, 0, nil, errors.Wrapf(RuleErrorCannotSpecifyCreatorAsAdditionalRoyalty,
			"_connectCreateNFT: cannot specify the post creator in the additional coin royalties map")
	}

	creatorRoyaltyBasisPoints := txMeta.NFTRoyaltyToCreatorBasisPoints + txMeta.NFTRoyaltyToCoinBasisPoints

	if creatorRoyaltyBasisPoints+additionalCoinNFTRoyaltiesBasisPoints+
		additionalDESONFTRoyaltiesBasisPoints > bav.Params.MaxNFTRoyaltyBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyHasTooManyBasisPoints
	}

	profileEntry := bav.GetProfileEntryForPublicKey(postEntry.PosterPublicKey)
	if profileEntry == nil || profileEntry.isDeleted {
		return 0, 0, nil, RuleErrorCantCreateNFTWithoutProfileEntry
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreateNFT: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorCreateNFTRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Since issuing N copies of an NFT multiplies the downstream processing overhead by N,
	// we charge a fee for each additional copy minted.
	// We do not need to check for overflow as these values are managed by the ParamUpdater.
	nftFee := txMeta.NumCopies * bav.GlobalParamsEntry.CreateNFTFeeNanos

	// Sanity check overflow and then ensure that the transaction covers the NFT fee.
	if math.MaxUint64-totalOutput < nftFee {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFTFee: nft Fee overflow")
	}
	totalOutput += nftFee
	if totalInput < totalOutput {
		return 0, 0, nil, RuleErrorCreateNFTWithInsufficientFunds
	}

	// Save a copy of the post entry so that we can safely modify it.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *postEntry

	// Update and save the post entry.
	postEntry.IsNFT = true
	postEntry.NumNFTCopies = txMeta.NumCopies
	if txMeta.IsForSale {
		postEntry.NumNFTCopiesForSale = txMeta.NumCopies
	}
	postEntry.HasUnlockable = txMeta.HasUnlockable
	postEntry.NFTRoyaltyToCreatorBasisPoints = txMeta.NFTRoyaltyToCreatorBasisPoints
	postEntry.NFTRoyaltyToCoinBasisPoints = txMeta.NFTRoyaltyToCoinBasisPoints
	postEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints = additionalDESONFTRoyalties
	postEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints = additionalCoinNFTRoyalties
	bav._setPostEntryMappings(postEntry)

	var extraData map[string][]byte
	if blockHeight >= bav.Params.ForkHeights.ExtraDataOnEntriesBlockHeight {
		// We don't have a previous entry here because we're creating the
		// entry from scratch.
		extraData = txn.ExtraData
	}

	// Add the appropriate NFT entries.
	for ii := uint64(1); ii <= txMeta.NumCopies; ii++ {
		nftEntry := &NFTEntry{
			OwnerPKID:         posterPKID.PKID,
			NFTPostHash:       txMeta.NFTPostHash,
			SerialNumber:      ii,
			IsForSale:         txMeta.IsForSale,
			MinBidAmountNanos: txMeta.MinBidAmountNanos,
			IsBuyNow:          isBuyNow,
			BuyNowPriceNanos:  buyNowPrice,
			ExtraData:         extraData,
		}
		bav._setNFTEntryMappings(nftEntry)
	}

	// Add an operation to the utxoOps list indicating we've created an NFT.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeCreateNFT,
		PrevPostEntry: prevPostEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectUpdateNFT(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeUpdateNFT {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*UpdateNFTMetadata)

	isBuyNow, buyNowPrice, err := bav._getBuyNowExtraData(txn, blockHeight)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateNFT: ")
	}

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotUpdateNonExistentNFT
	}

	// Verify the NFT is not a pending transfer.
	if prevNFTEntry.IsPending {
		return 0, 0, nil, RuleErrorCannotUpdatePendingNFTTransfer
	}

	// Get the postEntry so we can update the number of NFT copies for sale.
	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: non-existent postEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// We can't encrypt unlockable content if Buy Now is enabled.
	if postEntry.HasUnlockable && isBuyNow {
		return 0, 0, nil, errors.Wrapf(RuleErrorCannotHaveUnlockableAndBuyNowNFT, "_connectUpdateNFT: ")
	}

	// We can't have a Buy Now NFT with a buy now price below min bid amount
	if isBuyNow && txMeta.MinBidAmountNanos > buyNowPrice {
		return 0, 0, nil, errors.Wrapf(RuleErrorCannotHaveBuyNowPriceBelowMinBidAmountNanos, "_connectUpdateNFT: ")
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorUpdateNFTByNonOwner
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(prevNFTEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(prevNFTEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectUpdateNFT: prevNFTEntry %v is inconsistent with txMeta %v;"+
			" this should never happen.", prevNFTEntry, txMeta)
	}

	// At the moment, updates can only be made if the 'IsForSale' status of the NFT is changing.
	// As a result, you cannot change the MinBidAmountNanos of an NFT while it is for sale.
	if prevNFTEntry.IsForSale == txMeta.IsForSale {
		return 0, 0, nil, RuleErrorNFTUpdateMustUpdateIsForSaleStatus
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectUpdateNFT: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorUpdateNFTRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Now we are ready to update the NFT. Three things must happen:
	// 	(1) Update the NFT entry.
	//  (2) If the NFT entry is being updated to "is not for sale", kill all the bids.
	//  (3) Update the number of NFT copies for sale on the post entry.

	// Create the updated NFTEntry.
	newNFTEntry := &NFTEntry{
		LastOwnerPKID:     prevNFTEntry.LastOwnerPKID,
		OwnerPKID:         updaterPKID.PKID,
		NFTPostHash:       txMeta.NFTPostHash,
		SerialNumber:      txMeta.SerialNumber,
		IsForSale:         txMeta.IsForSale,
		MinBidAmountNanos: txMeta.MinBidAmountNanos,
		UnlockableText:    prevNFTEntry.UnlockableText,
		IsBuyNow:          isBuyNow,
		BuyNowPriceNanos:  buyNowPrice,
		// Keep the last accepted bid amount nanos from the previous entry since this
		// value is only updated when a new bid is accepted.
		LastAcceptedBidAmountNanos: prevNFTEntry.LastAcceptedBidAmountNanos,

		// Just copy the extra data from the previous entry when updating an NFT.
		// We do this because you're not allowed to update the ExtraData on an
		// NFTEntry.
		ExtraData: prevNFTEntry.ExtraData,
	}
	bav._setNFTEntryMappings(newNFTEntry)

	// If we are going from ForSale->NotForSale, delete all the NFTBidEntries for this NFT.
	deletedBidEntries := []*NFTBidEntry{}
	if prevNFTEntry.IsForSale && !txMeta.IsForSale {
		bidEntries := bav.GetAllNFTBidEntries(txMeta.NFTPostHash, txMeta.SerialNumber)
		for _, bidEntry := range bidEntries {
			deletedBidEntries = append(deletedBidEntries, bidEntry)
			bav._deleteNFTBidEntryMappings(bidEntry)
		}
	}

	// Save a copy of the post entry so that we can safely modify it.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *postEntry

	// Update the number of NFT copies that are for sale.
	if prevNFTEntry.IsForSale && !txMeta.IsForSale {
		// For sale --> Not for sale.
		postEntry.NumNFTCopiesForSale--
	} else if !prevNFTEntry.IsForSale && txMeta.IsForSale {
		// Not for sale --> For sale.
		postEntry.NumNFTCopiesForSale++
	}

	// Set the new postEntry.
	bav._setPostEntryMappings(postEntry)

	// Add an operation to the list at the end indicating we've connected an NFT update.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                 OperationTypeUpdateNFT,
		PrevNFTEntry:         prevNFTEntry,
		PrevPostEntry:        prevPostEntry,
		DeletedNFTBidEntries: deletedBidEntries,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectAcceptNFTBid(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTBid: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAcceptNFTBid {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTBid: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AcceptNFTBidMetadata)

	// Verify the NFT entry that is being bid on exists and is on sale.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		// We wrap these errors in order to differentiate versus _connectNFTBid().
		return 0, 0, nil, errors.Wrapf(RuleErrorNFTBidOnNonExistentNFTEntry, "_connectAcceptNFTBid: ")
	}
	if !prevNFTEntry.IsForSale {
		return 0, 0, nil, errors.Wrapf(RuleErrorNFTBidOnNFTThatIsNotForSale, "_connectAcceptNFTBid: ")
	}

	// Verify the NFT is not a pending transfer.
	if prevNFTEntry.IsPending {
		return 0, 0, nil, RuleErrorCannotAcceptBidForPendingNFTTransfer
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTBid: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorAcceptNFTBidByNonOwner
	}

	// Get the post entry, verify it exists.
	nftPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)

	// If this is an unlockable NFT, make sure that an unlockable string was provided.
	if nftPostEntry == nil || nftPostEntry.isDeleted {
		return 0, 0, nil, RuleErrorPostEntryNotFoundForAcceptedNFTBid
	}
	if nftPostEntry.HasUnlockable && len(txMeta.UnlockableText) == 0 {
		return 0, 0, nil, RuleErrorUnlockableNFTMustProvideUnlockableText
	}

	// Check the length of the UnlockableText.
	if uint64(len(txMeta.UnlockableText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorUnlockableTextLengthExceedsMax, "_connectAcceptNFTBid: "+
				"UnlockableTextLen = %d; Max length = %d",
			len(txMeta.UnlockableText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	totalInput, totalOutput, utxoOpsForTxn, err := bav._helpConnectNFTSold(HelpConnectNFTSoldStruct{
		NFTPostHash:    txMeta.NFTPostHash,
		SerialNumber:   txMeta.SerialNumber,
		BidderPKID:     txMeta.BidderPKID,
		BidAmountNanos: txMeta.BidAmountNanos,
		UnlockableText: txMeta.UnlockableText,

		BidderInputs:     txMeta.BidderInputs,
		BlockHeight:      blockHeight,
		Txn:              txn,
		TxHash:           txHash,
		VerifySignatures: verifySignatures,
	})
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid")
	}
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

type HelpConnectNFTSoldStruct struct {
	NFTPostHash     *BlockHash
	SerialNumber    uint64
	BidderPKID      *PKID
	BidAmountNanos  uint64
	UnlockableText  []byte
	PrevNFTBidEntry *NFTBidEntry

	// When an NFT owner accepts a bid, they must specify the bidder's UTXO inputs they will lock up
	// as payment for the purchase. This prevents the transaction from accidentally using UTXOs
	// that are used by future transactions.
	BidderInputs []*DeSoInput

	BlockHeight      uint32
	Txn              *MsgDeSoTxn
	TxHash           *BlockHash
	VerifySignatures bool
}

func (bav *UtxoView) _helpConnectNFTSold(args HelpConnectNFTSoldStruct) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if args.Txn.TxnMeta.GetTxnType() != TxnTypeAcceptNFTBid && args.Txn.TxnMeta.GetTxnType() != TxnTypeNFTBid {
		return 0, 0, nil, fmt.Errorf("_helpConnectNFTSold: This transaction must be either an AcceptNFTBid txn or a NFTBid txn")
	}
	nftKey := MakeNFTKey(args.NFTPostHash, args.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	// Get the post entry, verify it exists.
	nftPostEntry := bav.GetPostEntryForPostHash(args.NFTPostHash)

	// Get the poster's profile.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(nftPostEntry.PosterPublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: Profile missing for NFT pub key: %v %v",
			PkToStringMainnet(nftPostEntry.PosterPublicKey), PkToStringTestnet(nftPostEntry.PosterPublicKey))
	}
	// Save all the old values from the CreatorCoinEntry before we potentially
	// update them. Note that CreatorCoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CreatorCoinEntry

	// Additionally save all the other previous coin entries
	prevAdditionalCoinEntries := make(map[PKID]CoinEntry)
	profileEntriesMap := make(map[PKID]ProfileEntry)
	for pkidIter := range nftPostEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints {
		pkid := pkidIter
		pkBytes := bav.GetPublicKeyForPKID(&pkid)
		existingAdditionalProfileEntry := bav.GetProfileEntryForPublicKey(pkBytes)
		if existingAdditionalProfileEntry == nil || existingAdditionalProfileEntry.isDeleted {
			return 0, 0, nil, fmt.Errorf(
				"_helpConnectNFTSold: Profile missing for additional coin royalty "+
					"for pkid: %v, pub key: %v %v for post hash: %v",
				PkToStringMainnet(pkid[:]),
				PkToStringMainnet(pkBytes), PkToStringTestnet(pkBytes),
				hex.EncodeToString(nftPostEntry.PostHash[:]))
		}
		prevAdditionalCoinEntries[pkid] = existingAdditionalProfileEntry.CreatorCoinEntry
		profileEntriesMap[pkid] = *existingAdditionalProfileEntry
	}

	// Verify the NFT bid entry being accepted exists and has a bid consistent with the metadata.
	// If we did not require an AcceptNFTBid txn to have a bid amount, it would leave the door
	// open for an attack where someone replaces a high bid with a low bid after the owner accepts.
	nftBidKey := MakeNFTBidKey(args.BidderPKID, args.NFTPostHash, args.SerialNumber)
	nftBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	if nftBidEntry == nil || nftBidEntry.isDeleted {
		// NOTE: Users can submit a bid for SerialNumber zero as a blanket bid for any SerialNumber
		// in an NFT collection. Thus, we must check to see if a SerialNumber zero bid exists
		// for this bidder before we return an error.
		nftBidKey = MakeNFTBidKey(args.BidderPKID, args.NFTPostHash, uint64(0))
		nftBidEntry = bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
		if nftBidEntry == nil || nftBidEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorCantAcceptNonExistentBid, "_helpConnectNFTSold: ")
		}
	}

	if nftBidEntry.BidAmountNanos != args.BidAmountNanos {
		return 0, 0, nil, errors.Wrapf(RuleErrorAcceptedNFTBidAmountDoesNotMatch, "_helpConnectNFTSold: ")
	}

	bidderPublicKey := bav.GetPublicKeyForPKID(args.BidderPKID)

	//
	// Store starting balances of all the participants to check diff later.
	//
	// We assume the tip is right before the block in which this txn is about to be applied.
	tipHeight := uint32(0)
	blockHeight := args.BlockHeight
	if blockHeight > 0 {
		tipHeight = blockHeight - 1
	}
	sellerPublicKey := bav.GetPublicKeyForPKID(prevNFTEntry.OwnerPKID)
	sellerBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(sellerPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: Problem getting initial balance for seller pubkey: %v",
			PkToStringBoth(sellerPublicKey))
	}
	bidderBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(
		bidderPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: Problem getting initial balance for bidder pubkey: %v",
			PkToStringBoth(bidderPublicKey))
	}
	creatorBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(
		nftPostEntry.PosterPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: Problem getting initial balance for poster pubkey: %v",
			PkToStringBoth(nftPostEntry.PosterPublicKey))
	}
	desoRoyaltiesBalancesBefore := make(map[PKID]uint64)
	for pkidIter := range nftPostEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints {
		pkid := pkidIter
		pkBytes := bav.GetPublicKeyForPKID(&pkid)
		balanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(pkBytes, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_helpConnectNFTSold: Problem getting intial balance for additional DESO royalty for pubkey: %v",
				PkToStringBoth(pkBytes),
			)
		}
		desoRoyaltiesBalancesBefore[pkid] = balanceBefore
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	utxoOpsForTxn := []*UtxoOperation{}
	totalInput, totalOutput, utxoOpsFromBasicTransfer, err := bav._connectBasicTransfer(
		args.Txn, args.TxHash, blockHeight, args.VerifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_helpConnectNFTSold: ")
	}
	// Append the basic transfer utxoOps to our list
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsFromBasicTransfer...)

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, errors.Wrapf(RuleErrorAcceptNFTBidRequiresNonZeroInput, "_helpConnectNFTSold: ")
	}

	bidderChangeNanos := uint64(0)
	spentUtxoEntries := []*UtxoEntry{}
	// We only need to validate the bidder UTXOs when connecting an AcceptNFTBid transaction since the transactor and
	// the bidder are different users.  For NFTBid transactions on Buy Now NFTs, there are additional inputs to cover
	// the bid amount. We do not need to make explicitly make change for the bidder in that situation either.
	if args.Txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
		//
		// Validate bidder UTXOs.
		//
		if len(args.BidderInputs) == 0 {
			return 0, 0, nil, errors.Wrapf(RuleErrorAcceptedNFTBidMustSpecifyBidderInputs, "_helpConnectNFTSold: ")
		}
		totalBidderInput := uint64(0)
		for _, bidderInput := range args.BidderInputs {
			bidderUtxoKey := UtxoKey(*bidderInput)
			bidderUtxoEntry := bav.GetUtxoEntryForUtxoKey(&bidderUtxoKey)
			if bidderUtxoEntry == nil || bidderUtxoEntry.isSpent {
				return 0, 0, nil, errors.Wrapf(RuleErrorBidderInputForAcceptedNFTBidNoLongerExists, "_helpConnectNFTSold: ")
			}

			// Make sure that the utxo specified is actually from the bidder.
			if !reflect.DeepEqual(bidderUtxoEntry.PublicKey, bidderPublicKey) {
				return 0, 0, nil, errors.Wrapf(RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey, "_helpConnectNFTSold: ")
			}

			// If the utxo is from a block reward txn, make sure enough time has passed to
			// make it spendable.
			if _isEntryImmatureBlockReward(bidderUtxoEntry, blockHeight, bav.Params) {
				return 0, 0, nil, errors.Wrapf(RuleErrorInputSpendsImmatureBlockReward, "_helpConnectNFTSold: ")
			}
			totalBidderInput += bidderUtxoEntry.AmountNanos

			// Make sure we spend the utxo so that the bidder can't reuse it.
			utxoOp, err := bav._spendUtxo(&bidderUtxoKey)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_helpConnectNFTSold: Problem spending bidder utxo")
			}
			spentUtxoEntries = append(spentUtxoEntries, bidderUtxoEntry)

			// Track the UtxoOperations so we can rollback, and for Rosetta
			utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
		}

		if totalBidderInput < args.BidAmountNanos {
			return 0, 0, nil, errors.Wrapf(RuleErrorAcceptNFTBidderInputsInsufficientForBidAmount, "_helpConnectNFTSold: ")
		}

		// The bidder gets back any unspent nanos from the inputs specified.
		bidderChangeNanos = totalBidderInput - args.BidAmountNanos
	} else if args.Txn.TxnMeta.GetTxnType() == TxnTypeNFTBid {
		// If we're here, we know we're dealing with a "buy now" NFT because that is
		// the only situation in which a bid would result in an NFT being sold vs the
		// bid resting on the NFT (and waiting for AcceptNFTBid to trigger).

		bidAmountNanos := args.BidAmountNanos
		// Check that the bid amount is non-zero.
		if bidAmountNanos == 0 {
			return 0, 0, nil, errors.Wrapf(RuleErrorBuyNowNFTBidMustBidNonZeroDeSo, "_helpConnectNFTSold: ")
		}

		// Check that the bid amount is greater than the min bid amount.
		// This check isn't really necessary because we know that the NFT bid amount
		// exceeds the buy now value by the time we get here, and therefore implicitly exceeds
		// the MinBidAmount, but we check it regardless.
		if bidAmountNanos < prevNFTEntry.MinBidAmountNanos {
			return 0, 0, nil, errors.Wrapf(RuleErrorBuyNowNFTBidMustHaveMinBidAmountNanos, "_helpConnectNFTSold: ")
		}

		// The amount of DeSo being bid counts as output being spent by
		// this transaction, so add it to the transaction output and check that
		// the resulting output does not exceed the total input.
		//
		// Check for overflow of the outputs before adding.
		if totalOutput > math.MaxUint64-bidAmountNanos {
			return 0, 0, nil, errors.Wrapf(RuleErrorNFTBidTxnOutputWithInvalidBidAmount, "_helpConnectNFTSold: ")
		}

		totalOutput += bidAmountNanos
		// It's assumed the caller code will check that things like output <= input,
		// we check it here just in case...
		if totalInput < totalOutput {
			return 0, 0, nil, errors.Wrapf(RuleErrorBuyNowNFTBidTxnOutputExceedsInput, "_helpConnectNFTSold: Input: %v, Output: %v", totalInput, totalOutput)
		}
	}

	// The amount of deso that should go to the original creator from this purchase.
	// Calculated as: (BidAmountNanos * NFTRoyaltyToCreatorBasisPoints) / (100 * 100)
	creatorRoyaltyNanos := IntDiv(
		IntMul(
			big.NewInt(int64(args.BidAmountNanos)),
			big.NewInt(int64(nftPostEntry.NFTRoyaltyToCreatorBasisPoints))),
		big.NewInt(100*100)).Uint64()
	// The amount of deso that should go to the original creator's coin from this purchase.
	// Calculated as: (BidAmountNanos * NFTRoyaltyToCoinBasisPoints) / (100 * 100)
	creatorCoinRoyaltyNanos := IntDiv(
		IntMul(
			big.NewInt(int64(args.BidAmountNanos)),
			big.NewInt(int64(nftPostEntry.NFTRoyaltyToCoinBasisPoints))),
		big.NewInt(100*100)).Uint64()
	//glog.Infof("Bid amount: %d, coin basis points: %d, coin royalty: %d",
	//	txMeta.BidAmountNanos, nftPostEntry.NFTRoyaltyToCoinBasisPoints, creatorCoinRoyaltyNanos)

	constructRoyalties := func(royaltyMap map[PKID]uint64) (
		_additionalRoyaltiesNanos uint64, _additionalRoyalties []*PublicKeyRoyaltyPair, _err error) {
		additionalRoyaltiesNanos := uint64(0)
		var additionalRoyalties []*PublicKeyRoyaltyPair
		for pkidIter, bps := range royaltyMap {
			pkid := pkidIter
			royaltyNanos := IntDiv(
				IntMul(
					big.NewInt(int64(args.BidAmountNanos)),
					big.NewInt(int64(bps))),
				big.NewInt(100*100)).Uint64()
			if math.MaxUint64-royaltyNanos < additionalRoyaltiesNanos {
				return 0, nil, RuleErrorNFTRoyaltyOverflow
			}
			pkBytes := bav.GetPublicKeyForPKID(&pkid)
			if len(pkBytes) != btcec.PubKeyBytesLenCompressed {
				return 0, nil, fmt.Errorf(
					"_helpConnectNFTSold: invalid public key found for pkid in additional DESO royalty map")
			}
			if _, err = btcec.ParsePubKey(pkBytes, btcec.S256()); err != nil {
				return 0, nil, errors.Wrapf(err, "Unable to parse public key")
			}

			if royaltyNanos > 0 {
				additionalRoyaltiesNanos += royaltyNanos
				additionalRoyalties = append(additionalRoyalties, &PublicKeyRoyaltyPair{
					PublicKey:          pkBytes,
					RoyaltyAmountNanos: royaltyNanos,
				})
			}
		}
		// We must sort the royalties in a deterministic way or else the UTXOs that we
		// generate for the royalties will have a random order. This would cause one node
		// to believe UTXO zero is some value, while another node believes it to be a
		// different value because it put a different UTXO in that index.
		sort.Slice(additionalRoyalties, func(ii, jj int) bool {
			iiPkStr := PkToString(additionalRoyalties[ii].PublicKey, bav.Params)
			jjPkStr := PkToString(additionalRoyalties[jj].PublicKey, bav.Params)
			// Generally, we should never have to break a tie because a public key
			// cannot appear in the royalties more than once. But we do it here just
			// to be safe.
			if iiPkStr == jjPkStr {
				return additionalRoyalties[ii].RoyaltyAmountNanos < additionalRoyalties[jj].RoyaltyAmountNanos
			}
			return iiPkStr < jjPkStr
		})
		return additionalRoyaltiesNanos, additionalRoyalties, nil
	}

	additionalDESORoyaltiesNanos, additionalDESORoyalties, err := constructRoyalties(
		nftPostEntry.AdditionalNFTRoyaltiesToCreatorsBasisPoints)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err,
			"_helpConnectNFTSold: Error constructing royalties for additional creator royalties: ")
	}

	additionalCoinRoyaltyNanos, additionalCoinRoyalties, err := constructRoyalties(
		nftPostEntry.AdditionalNFTRoyaltiesToCoinsBasisPoints)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err,
			"_helpConnectNFTSold: Error constructing royalties for additional coin royalties: ")
	}

	// Sanity check that the royalties are reasonable and won't cause underflow.
	if args.BidAmountNanos < (creatorRoyaltyNanos + creatorCoinRoyaltyNanos +
		additionalCoinRoyaltyNanos + additionalDESORoyaltiesNanos) {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: sum of royalties (%d, %d, %d, %d) is greater than bid amount (%d)",
			creatorRoyaltyNanos, creatorCoinRoyaltyNanos, additionalDESORoyaltiesNanos, additionalCoinRoyaltyNanos,
			args.BidAmountNanos)
	}

	bidAmountMinusRoyalties := args.BidAmountNanos - creatorRoyaltyNanos - creatorCoinRoyaltyNanos -
		additionalCoinRoyaltyNanos - additionalDESORoyaltiesNanos

	if args.VerifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the poster's
		// public key.
	}

	// Now we are ready to accept the bid. When we accept, the following must happen:
	// 	(1) Update the nft entry with the new owner and set it as "not for sale".
	//  (2) Delete all of the bids on this NFT since they are no longer relevant.
	//  (3) Pay the seller.
	//  (4) Pay royalties to the original creator.
	//  (5) Pay change to the bidder.
	//  (6) Add creator coin royalties to deso locked.
	//  (7) Decrement the nftPostEntry NumNFTCopiesForSale.

	// (1) Set an appropriate NFTEntry for the new owner.

	newNFTEntry := &NFTEntry{
		LastOwnerPKID:  prevNFTEntry.OwnerPKID,
		OwnerPKID:      args.BidderPKID,
		NFTPostHash:    args.NFTPostHash,
		SerialNumber:   args.SerialNumber,
		IsForSale:      false,
		UnlockableText: args.UnlockableText,
		// We automatically flip IsBuyNow to false. Otherwise, someone could buy this NFT from them.
		IsBuyNow: false,

		LastAcceptedBidAmountNanos: args.BidAmountNanos,
	}
	bav._setNFTEntryMappings(newNFTEntry)

	// append the accepted bid entry to the list of accepted bid entries
	prevAcceptedBidHistory := bav.GetAcceptNFTBidHistoryForNFTKey(&nftKey)
	acceptedNFTBidEntry := nftBidEntry.Copy()
	acceptedNFTBidEntry.AcceptedBlockHeight = &blockHeight
	newAcceptedBidHistory := append(*prevAcceptedBidHistory, acceptedNFTBidEntry)
	bav._setAcceptNFTBidHistoryMappings(nftKey, &newAcceptedBidHistory)

	// (2) Iterate over all the NFTBidEntries for this NFT and delete them.
	bidEntries := bav.GetAllNFTBidEntries(args.NFTPostHash, args.SerialNumber)
	if len(bidEntries) == 0 && nftBidEntry.SerialNumber != 0 {
		// Quick sanity check to make sure that we found bid entries. There should be at least 1.
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: found zero bid entries to delete; this should never happen.")
	}
	deletedBidEntries := []*NFTBidEntry{}
	for _, bidEntry := range bidEntries {
		deletedBidEntries = append(deletedBidEntries, bidEntry)
		bav._deleteNFTBidEntryMappings(bidEntry)
	}
	// If this is a SerialNumber zero BidEntry, we must delete it specifically.
	if nftBidEntry.SerialNumber == uint64(0) {
		deletedBidEntries = append(deletedBidEntries, nftBidEntry)
		bav._deleteNFTBidEntryMappings(nftBidEntry)
	}

	nftPaymentUtxoKeys := []*UtxoKey{}
	// This may start negative but that's OK because the first thing we do is increment it
	// in createUTXO
	nextUtxoIndex := len(args.Txn.TxOutputs) - 1
	createUTXO := func(amountNanos uint64, publicKeyArg []byte, utxoType UtxoType) (_err error) {
		publicKey := publicKeyArg

		// nextUtxoIndex is guaranteed to be >= 0 after this increment
		nextUtxoIndex += 1
		royaltyOutputKey := &UtxoKey{
			TxID:  *args.TxHash,
			Index: uint32(nextUtxoIndex),
		}

		utxoEntry := UtxoEntry{
			AmountNanos: amountNanos,
			PublicKey:   publicKey,
			BlockHeight: blockHeight,
			UtxoType:    utxoType,

			UtxoKey: royaltyOutputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}

		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return errors.Wrapf(err, "_helpConnectNFTSold: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, royaltyOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)

		return nil
	}

	// (3) Pay the seller by creating a new entry for this output and add it to the view.
	if err = createUTXO(bidAmountMinusRoyalties, sellerPublicKey, UtxoTypeNFTSeller); err != nil {
		return 0, 0, nil, errors.Wrapf(
			err, "_helpConnectNFTSold: Problem creating UTXO for seller: ")
	}

	// (4) Pay royalties to the original artist.
	if creatorRoyaltyNanos > 0 {
		if err = createUTXO(creatorRoyaltyNanos, nftPostEntry.PosterPublicKey, UtxoTypeNFTCreatorRoyalty); err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_helpConnectNFTsold: Problem creating UTXO for creator royalty: ")
		}
	}

	// (4-a) Pay DESO royalties to any additional royalties specified
	for _, publicKeyRoyaltyPairIter := range additionalDESORoyalties {
		publicKeyRoyaltyPair := publicKeyRoyaltyPairIter
		if publicKeyRoyaltyPair.RoyaltyAmountNanos > 0 {
			if err = createUTXO(publicKeyRoyaltyPair.RoyaltyAmountNanos, publicKeyRoyaltyPair.PublicKey,
				UtxoTypeNFTAdditionalDESORoyalty); err != nil {
				return 0, 0, nil, errors.Wrapf(
					err, "_helpConnectNFTSold: Problem creating UTXO for additional DESO royalty: ")
			}
		}
	}

	// (5) Give any change back to the bidder.
	if bidderChangeNanos > 0 {
		if err = createUTXO(bidderChangeNanos, bidderPublicKey, UtxoTypeNFTCreatorRoyalty); err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_helpConnectNFTSold: Problem creating UTXO for bidder change: ")
		}
	}

	// We don't do a royalty if the number of coins in circulation is too low.
	//
	// Note that it's OK to cast to uint64 for creator coins because we check to make
	// sure they never exceed this value.
	if existingProfileEntry.CreatorCoinEntry.CoinsInCirculationNanos.Uint64() < bav.Params.CreatorCoinAutoSellThresholdNanos {
		creatorCoinRoyaltyNanos = 0
	}

	// (6) Add creator coin royalties to deso locked. If the number of coins in circulation is
	// less than the "auto sell threshold" we burn the deso.
	newCoinEntry := prevCoinEntry
	if creatorCoinRoyaltyNanos > 0 {
		// Make a copy of the previous coin entry. It has no pointers, so a direct copy is ok.
		newCoinEntry.DeSoLockedNanos += creatorCoinRoyaltyNanos
		existingProfileEntry.CreatorCoinEntry = newCoinEntry
		bav._setProfileEntryMappings(existingProfileEntry)
	}

	// (6-a) Add additional coin royalties to deso locked. If the number of coins in circulation is less than
	// the "auto sell threshold" we burn the deso.
	var newCoinRoyaltyCoinEntries []CoinEntry
	for kk := range additionalCoinRoyalties {
		publicKeyRoyaltyPair := additionalCoinRoyalties[kk]
		// Get coin entry
		profileEntry := profileEntriesMap[*bav.GetPKIDForPublicKey(publicKeyRoyaltyPair.PublicKey).PKID]
		// We don't do a royalty if the number of coins in circulation is too low.
		if profileEntry.CreatorCoinEntry.CoinsInCirculationNanos.Uint64() < bav.Params.CreatorCoinAutoSellThresholdNanos {
			additionalCoinRoyalties[kk].RoyaltyAmountNanos = 0
			publicKeyRoyaltyPair.RoyaltyAmountNanos = 0
		}
		// Make a copy of the previous coin entry. It has no pointers, so a direct copy is ok.
		newCoinRoyaltyCoinEntry := profileEntry.CreatorCoinEntry
		if publicKeyRoyaltyPair.RoyaltyAmountNanos > 0 {
			newCoinRoyaltyCoinEntry.DeSoLockedNanos += publicKeyRoyaltyPair.RoyaltyAmountNanos
			profileEntry.CreatorCoinEntry = newCoinRoyaltyCoinEntry
			bav._setProfileEntryMappings(&profileEntry)
		}
		newCoinRoyaltyCoinEntries = append(newCoinRoyaltyCoinEntries, newCoinRoyaltyCoinEntry)
	}

	// (7) Save a copy of the previous postEntry and then decrement NumNFTCopiesForSale.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *nftPostEntry
	nftPostEntry.NumNFTCopiesForSale--
	bav._setPostEntryMappings(nftPostEntry)

	// Create an Operation to add to the end of the list. Fill all fields except the type which depends upon
	// if this is an AcceptNFTBid transaction or an NFTBid transaction.
	transactionUtxoOp := &UtxoOperation{
		PrevNFTEntry:               prevNFTEntry,
		PrevPostEntry:              prevPostEntry,
		PrevCoinEntry:              &prevCoinEntry,
		PrevCoinRoyaltyCoinEntries: prevAdditionalCoinEntries,
		DeletedNFTBidEntries:       deletedBidEntries,
		NFTPaymentUtxoKeys:         nftPaymentUtxoKeys,
		NFTSpentUtxoEntries:        spentUtxoEntries,
		PrevAcceptedNFTBidEntries:  prevAcceptedBidHistory,
		PrevNFTBidEntry:            args.PrevNFTBidEntry,
	}
	if args.Txn.TxnMeta.GetTxnType() == TxnTypeAcceptNFTBid {
		transactionUtxoOp.Type = OperationTypeAcceptNFTBid
		// Rosetta fields
		transactionUtxoOp.AcceptNFTBidCreatorPublicKey = nftPostEntry.PosterPublicKey
		transactionUtxoOp.AcceptNFTBidBidderPublicKey = bidderPublicKey
		transactionUtxoOp.AcceptNFTBidCreatorRoyaltyNanos = creatorCoinRoyaltyNanos
		transactionUtxoOp.AcceptNFTBidCreatorDESORoyaltyNanos = creatorRoyaltyNanos
		if len(additionalCoinRoyalties) > 0 {
			transactionUtxoOp.AcceptNFTBidAdditionalCoinRoyalties = additionalCoinRoyalties
		}
		if len(additionalDESORoyalties) > 0 {
			transactionUtxoOp.AcceptNFTBidAdditionalDESORoyalties = additionalDESORoyalties
		}
	} else if args.Txn.TxnMeta.GetTxnType() == TxnTypeNFTBid {
		transactionUtxoOp.Type = OperationTypeNFTBid
		// Rosetta fields
		transactionUtxoOp.NFTBidCreatorPublicKey = nftPostEntry.PosterPublicKey
		transactionUtxoOp.NFTBidBidderPublicKey = bidderPublicKey
		transactionUtxoOp.NFTBidCreatorRoyaltyNanos = creatorCoinRoyaltyNanos
		transactionUtxoOp.NFTBidCreatorDESORoyaltyNanos = creatorRoyaltyNanos
		if len(additionalCoinRoyalties) > 0 {
			transactionUtxoOp.NFTBidAdditionalCoinRoyalties = additionalCoinRoyalties
		}
		if len(additionalDESORoyalties) > 0 {
			transactionUtxoOp.NFTBidAdditionalDESORoyalties = additionalDESORoyalties
		}
	} else {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: TxnType %v is not supported",
			args.Txn.TxnMeta.GetTxnType())
	}

	// Add an operation to the list at the end indicating we've connected an NFT bid or Accept NFT Bid transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, transactionUtxoOp)

	// HARDCORE SANITY CHECK:
	//  - Before returning we do one more sanity check that money hasn't been printed.
	//
	// Seller balance diff:
	sellerBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(sellerPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: Problem getting final balance for seller pubkey: %v",
			PkToStringBoth(sellerPublicKey))
	}
	sellerDiff := int64(sellerBalanceAfter) - int64(sellerBalanceBefore)
	// Bidder balance diff (only relevant if bidder != seller):
	bidderDiff := int64(0)
	if !reflect.DeepEqual(bidderPublicKey, sellerPublicKey) {
		bidderBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(bidderPublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_helpConnectNFTSold: Problem getting final balance for bidder pubkey: %v",
				PkToStringBoth(bidderPublicKey))
		}
		bidderDiff = int64(bidderBalanceAfter) - int64(bidderBalanceBefore)
	}
	// Creator balance diff (only relevant if creator != seller and creator != bidder):
	creatorDiff := int64(0)
	if !reflect.DeepEqual(nftPostEntry.PosterPublicKey, sellerPublicKey) &&
		!reflect.DeepEqual(nftPostEntry.PosterPublicKey, bidderPublicKey) {
		creatorBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(nftPostEntry.PosterPublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_helpConnectNFTSold: Problem getting final balance for poster pubkey: %v",
				PkToStringBoth(nftPostEntry.PosterPublicKey))
		}
		creatorDiff = int64(creatorBalanceAfter) - int64(creatorBalanceBefore)
	}
	// Creator coin diff:
	coinDiff := int64(newCoinEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)
	// Now the actual check. Use bigints to avoid getting fooled by overflow.
	sellerPlusBidderDiff := big.NewInt(0).Add(big.NewInt(sellerDiff), big.NewInt(bidderDiff))
	creatorPlusCoinDiff := big.NewInt(0).Add(big.NewInt(creatorDiff), big.NewInt(coinDiff))
	// Compute additional DESO royalties diff
	additionalDESORoyaltiesDiff := big.NewInt(0)
	for pkidIter, balanceBefore := range desoRoyaltiesBalancesBefore {
		pkid := pkidIter
		// Only relevant if additional royalty recipient != seller && != bidder (note: creator cannot be specified in
		// additional DESO (or coin) royalties maps, so we do not need to check against that public key)
		pkBytes := bav.GetPublicKeyForPKID(&pkid)
		if reflect.DeepEqual(pkBytes, bidderPublicKey) || reflect.DeepEqual(pkBytes, sellerPublicKey) {
			continue
		}
		balanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(pkBytes, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_helpConnectNFTSold: Problem getting final balance for additional DESO royalty for pubkey: %v",
				PkToStringBoth(pkBytes))
		}
		additionalDESORoyaltiesDiff = additionalDESORoyaltiesDiff.Add(
			additionalDESORoyaltiesDiff,
			big.NewInt(int64(balanceAfter-balanceBefore)),
		)
	}

	// Compute additional coin royalties diff
	additionalCoinRoyaltiesDiff := big.NewInt(0)

	// First, iterate through all the new ones and add them up.
	for _, coinEntry := range newCoinRoyaltyCoinEntries {
		additionalCoinRoyaltiesDiff.Add(
			additionalCoinRoyaltiesDiff,
			big.NewInt(int64(coinEntry.DeSoLockedNanos)))
	}

	// Then go through all the previous additional coin entries and subtract them.
	for _, coinEntry := range prevAdditionalCoinEntries {
		additionalCoinRoyaltiesDiff.Sub(
			additionalCoinRoyaltiesDiff,
			big.NewInt(int64(coinEntry.DeSoLockedNanos)),
		)
	}

	totalAdditionalRoyaltiesDiff := big.NewInt(0).Add(additionalDESORoyaltiesDiff, additionalCoinRoyaltiesDiff)

	totalDiff := big.NewInt(0).Add(sellerPlusBidderDiff, creatorPlusCoinDiff)
	totalDiff = totalDiff.Add(totalDiff, totalAdditionalRoyaltiesDiff)
	if totalDiff.Cmp(big.NewInt(0)) > 0 {
		return 0, 0, nil, fmt.Errorf(
			"_helpConnectNFTSold: Sum of participant diffs is >0 (%d, %d, %d, %d, %d, %d)",
			sellerDiff, bidderDiff, creatorDiff, coinDiff, additionalDESORoyaltiesDiff.Int64(),
			additionalCoinRoyaltiesDiff.Int64())
	}

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectNFTBid(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {
	if bav.GlobalParamsEntry.MaxCopiesPerNFT == 0 {
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: called with zero MaxCopiesPerNFT")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNFTBid {
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NFTBidMetadata)

	// Verify that the postEntry being bid on exists, is an NFT, and supports the given serial #.
	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, RuleErrorNFTBidOnNonExistentPost
	} else if !postEntry.IsNFT {
		return 0, 0, nil, RuleErrorNFTBidOnPostThatIsNotAnNFT
	} else if txMeta.SerialNumber > postEntry.NumNFTCopies {
		return 0, 0, nil, RuleErrorNFTBidOnInvalidSerialNumber
	}

	// Validate the nftEntry.  Note that there is a special case where a bidder can submit a bid
	// on SerialNumber zero.  This acts as a blanket bid on any serial number version of this NFT
	// As a result, the nftEntry will be nil and should not be validated.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	nftEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	bidderPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if bidderPKID == nil || bidderPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: PKID for bidder public "+
			"key %v doesn't exist; this should never happen", string(txn.PublicKey))
	}

	// Save a copy of the bid entry so that we can use it in the disconnect.
	nftBidKey := MakeNFTBidKey(bidderPKID.PKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	isBuyNowBid := false
	if txMeta.SerialNumber != uint64(0) {
		// Verify the NFT entry that is being bid on exists.
		if nftEntry == nil || nftEntry.isDeleted {
			return 0, 0, nil, RuleErrorNFTBidOnNonExistentNFTEntry
		}

		// Verify the NFT entry being bid on is for sale.
		if !nftEntry.IsForSale {
			return 0, 0, nil, RuleErrorNFTBidOnNFTThatIsNotForSale
		}

		// Verify the NFT is not a pending transfer.
		if nftEntry.IsPending {
			return 0, 0, nil, RuleErrorCannotBidForPendingNFTTransfer
		}

		// Verify that the bidder is not the current owner of the NFT.
		if reflect.DeepEqual(nftEntry.OwnerPKID, bidderPKID.PKID) {
			return 0, 0, nil, RuleErrorNFTOwnerCannotBidOnOwnedNFT
		}

		// Verify that the bid amount is greater than the min bid amount for this NFT.
		// We allow BidAmountNanos to be 0 if there exists a previous bid entry. A value of 0 indicates that we should delete the entry.
		if txMeta.BidAmountNanos < nftEntry.MinBidAmountNanos && !(txMeta.BidAmountNanos == 0 && prevNFTBidEntry != nil) {
			return 0, 0, nil, RuleErrorNFTBidLessThanMinBidAmountNanos
		}
		// Verify that we are not bidding on a Buy Now NFT before the Buy Now NFT Block Height. This should never happen.
		if nftEntry.IsBuyNow &&
			blockHeight < bav.Params.ForkHeights.BuyNowAndNFTSplitsBlockHeight {

			return 0, 0, nil, errors.Wrapf(RuleErrorBuyNowNFTBeforeBlockHeight, "_connectNFTBid: ")
		}
		// If the NFT is a Buy Now NFT and the bid amount is greater than the Buy Now Price, we treat this bid as a
		// a purchase. We also make sure that the Bid Amount is greater than 0. A bid amount of 0 would signify the
		// cancellation of a previous bid. It is possible to have the Buy Now Price be 0 nanos, but it would require
		// a bid of at least 1 nano.
		if nftEntry.IsBuyNow && txMeta.BidAmountNanos >= nftEntry.BuyNowPriceNanos && txMeta.BidAmountNanos > 0 {
			isBuyNowBid = true
		}
	}

	deletePrevBidAndSetNewBid := func() {
		// If an old bid exists, delete it.
		if prevNFTBidEntry != nil {
			bav._deleteNFTBidEntryMappings(prevNFTBidEntry)
		}
		// If the new bid has a non-zero amount, set it.
		if txMeta.BidAmountNanos != 0 {
			// Zero bids are not allowed, submitting a zero bid effectively withdraws a prior bid.
			newBidEntry := &NFTBidEntry{
				BidderPKID:     bidderPKID.PKID,
				NFTPostHash:    txMeta.NFTPostHash,
				SerialNumber:   txMeta.SerialNumber,
				BidAmountNanos: txMeta.BidAmountNanos,
			}
			bav._setNFTBidEntryMappings(newBidEntry)
		}
	}

	// If this is a bid on an NFT that is not "Buy Now" enabled or a bid below the Buy Now Price, simply create the bid.
	if !isBuyNowBid {
		// Connect basic txn to get the total input and the total output without
		// considering the transaction metadata.
		totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
			txn, txHash, blockHeight, verifySignatures)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNFTBid: ")
		}
		// We assume the tip is right before the block in which this txn is about to be applied.
		tipHeight := uint32(0)
		if blockHeight > 0 {
			tipHeight = blockHeight - 1
		}
		// Verify that the transaction creator has sufficient deso to create the bid.
		spendableBalance, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNFTBid: Error getting bidder balance: ")
		} else if txMeta.BidAmountNanos > spendableBalance &&
			blockHeight > bav.Params.ForkHeights.BrokenNFTBidsFixBlockHeight {

			return 0, 0, nil, RuleErrorInsufficientFundsForNFTBid
		}
		// Force the input to be non-zero so that we can prevent replay attacks.
		if totalInput == 0 {
			return 0, 0, nil, RuleErrorNFTBidRequiresNonZeroInput
		}
		if verifySignatures {
			// _connectBasicTransfer has already checked that the transaction is
			// signed by the top-level public key, which we take to be the poster's
			// public key.
		}

		// Delete the previous bid and set the new bid.
		deletePrevBidAndSetNewBid()

		// Add an operation to the list at the end indicating we've connected an NFT bid.
		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:            OperationTypeNFTBid,
			PrevNFTBidEntry: prevNFTBidEntry,
		})

		return totalInput, totalOutput, utxoOpsForTxn, nil
	} else {
		// For bids above the Buy Now Price on Buy Now NFTs, we delete the prev bid if it exists and create a bid that
		// will get deleted in the _helpConnectNFTSold logic. This allows us to reuse the code that handles the royalty
		// payouts and NFT ownership changes that is used in _connectAcceptNFTBid.
		deletePrevBidAndSetNewBid()

		// Okay here's where the fun happens. We are submitting a bid on a Buy Now enabled NFT.
		// We create the bid then we call the _helpConnectNFTSold to handle the royalty payout
		// logic and such.
		//
		// Note that by the time we get here, we have verified that the bid amount exceeds the
		// buy now price.
		totalInput, totalOutput, utxoOpsForTxn, err := bav._helpConnectNFTSold(HelpConnectNFTSoldStruct{
			NFTPostHash:     txMeta.NFTPostHash,
			SerialNumber:    txMeta.SerialNumber,
			BidderPKID:      bidderPKID.PKID,
			BidAmountNanos:  txMeta.BidAmountNanos,
			PrevNFTBidEntry: prevNFTBidEntry,

			BidderInputs: []*DeSoInput{},

			BlockHeight:      blockHeight,
			Txn:              txn,
			TxHash:           txHash,
			VerifySignatures: verifySignatures,
		})
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNFTBid: ")
		}
		return totalInput, totalOutput, utxoOpsForTxn, nil
	}
}

func (bav *UtxoView) _connectNFTTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorNFTTransferBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNFTTransfer {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NFTTransferMetadata)

	// Check that the specified receiver public key is valid.
	if len(txMeta.ReceiverPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, RuleErrorNFTTransferInvalidReceiverPubKeySize
	}

	// Check that the sender and receiver public keys are different.
	if reflect.DeepEqual(txn.PublicKey, txMeta.ReceiverPublicKey) {
		return 0, 0, nil, RuleErrorNFTTransferCannotTransferToSelf
	}

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotTransferNonExistentNFT
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorNFTTransferByNonOwner
	}

	// Fetch the receiver's PKID and make sure it exists.
	receiverPKID := bav.GetPKIDForPublicKey(txMeta.ReceiverPublicKey)
	// Sanity check that we found a PKID entry for these pub keys (should never fail).
	if receiverPKID == nil || receiverPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectNFTTransfer: Found nil or deleted PKID for receiver, this should never "+
				"happen. Receiver pubkey: %v", PkToStringMainnet(txMeta.ReceiverPublicKey))
	}

	// Make sure that the NFT entry is not for sale.
	if prevNFTEntry.IsForSale {
		return 0, 0, nil, RuleErrorCannotTransferForSaleNFT
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(prevNFTEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(prevNFTEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: prevNFTEntry %v is inconsistent with txMeta %v;"+
			" this should never happen.", prevNFTEntry, txMeta)
	}

	// Get the postEntry so we can check for unlockable content.
	nftPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if nftPostEntry == nil || nftPostEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectNFTTransfer: non-existent nftPostEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// If the post entry requires the NFT to have unlockable text, make sure it is provided.
	if nftPostEntry.HasUnlockable && len(txMeta.UnlockableText) == 0 {
		return 0, 0, nil, RuleErrorCannotTransferUnlockableNFTWithoutUnlockable
	}

	// Check the length of the UnlockableText.
	if uint64(len(txMeta.UnlockableText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorUnlockableTextLengthExceedsMax, "_connectNFTTransfer: "+
				"UnlockableTextLen = %d; Max length = %d",
			len(txMeta.UnlockableText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNFTTransfer: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorNFTTransferRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the NFT owner's
		// public key.
	}

	// Now we are ready to transfer the NFT.

	// Make a copy of the previous NFT
	newNFTEntry := *prevNFTEntry
	// Update the fields that were set during this transfer.
	newNFTEntry.LastOwnerPKID = prevNFTEntry.OwnerPKID
	newNFTEntry.OwnerPKID = receiverPKID.PKID
	newNFTEntry.UnlockableText = txMeta.UnlockableText
	newNFTEntry.IsPending = true

	// Set the new entry in the view.
	bav._deleteNFTEntryMappings(prevNFTEntry)
	bav._setNFTEntryMappings(&newNFTEntry)

	// Add an operation to the list at the end indicating we've connected an NFT update.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:         OperationTypeNFTTransfer,
		PrevNFTEntry: prevNFTEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectAcceptNFTTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorAcceptNFTTransferBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAcceptNFTTransfer {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTTransfer: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AcceptNFTTransferMetadata)

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if prevNFTEntry == nil || prevNFTEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotAcceptTransferOfNonExistentNFT
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTTransfer: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(prevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorAcceptNFTTransferByNonOwner
	}

	// Verify that the NFT is actually pending.
	if !prevNFTEntry.IsPending {
		return 0, 0, nil, RuleErrorAcceptNFTTransferForNonPendingNFT
	}

	// Sanity check that the NFT entry is not for sale.
	if prevNFTEntry.IsForSale {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTTransfer: attempted to accept NFT transfer of NFT that is for "+
				"sale. This should never happen; txMeta %v.", txMeta)
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(prevNFTEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(prevNFTEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectAcceptNFTTransfer: prevNFTEntry %v is "+
			"inconsistent with txMeta %v; this should never happen.", prevNFTEntry, txMeta)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTTransfer: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorAcceptNFTTransferRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the NFT owner's
		// public key.
	}

	// Now we are ready to transfer the NFT.

	// Create the updated NFTEntry (everything the same except for IsPending) and set it.
	newNFTEntry := *prevNFTEntry
	newNFTEntry.IsPending = false
	bav._deleteNFTEntryMappings(prevNFTEntry)
	bav._setNFTEntryMappings(&newNFTEntry)

	// Add an operation for the accepted NFT transfer.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:         OperationTypeAcceptNFTTransfer,
		PrevNFTEntry: prevNFTEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectBurnNFT(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < bav.Params.ForkHeights.NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, RuleErrorBurnNFTBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeBurnNFT {
		return 0, 0, nil, fmt.Errorf("_connectBurnNFT: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*BurnNFTMetadata)

	// Verify the NFT entry exists.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	nftEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if nftEntry == nil || nftEntry.isDeleted {
		return 0, 0, nil, RuleErrorCannotBurnNonExistentNFT
	}

	// Verify that the updater is the owner of the NFT.
	updaterPKID := bav.GetPKIDForPublicKey(txn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectBurnNFT: non-existent updaterPKID: %s",
			PkToString(txn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(nftEntry.OwnerPKID, updaterPKID.PKID) {
		return 0, 0, nil, RuleErrorBurnNFTByNonOwner
	}

	// Verify that the NFT is not for sale.
	if nftEntry.IsForSale {
		return 0, 0, nil, RuleErrorCannotBurnNFTThatIsForSale
	}

	// Sanity check that the NFT entry is correct.
	if !reflect.DeepEqual(nftEntry.NFTPostHash, txMeta.NFTPostHash) ||
		!reflect.DeepEqual(nftEntry.SerialNumber, txMeta.SerialNumber) {
		return 0, 0, nil, fmt.Errorf("_connectBurnNFT: nftEntry %v is "+
			"inconsistent with txMeta %v; this should never happen.", nftEntry, txMeta)
	}

	// Get the postEntry so we can increment the burned copies count.
	nftPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if nftPostEntry == nil || nftPostEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectBurnNFT: non-existent nftPostEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectBurnNFT: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorBurnNFTRequiresNonZeroInput
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the NFT owner's
		// public key.
	}

	// Create a backup before we burn the NFT.
	prevNFTEntry := *nftEntry

	// Delete the NFT.
	bav._deleteNFTEntryMappings(nftEntry)

	// Save a copy of the previous postEntry and then increment NumNFTCopiesBurned.
	prevPostEntry := *nftPostEntry
	nftPostEntry.NumNFTCopiesBurned++
	bav._deletePostEntryMappings(&prevPostEntry)
	bav._setPostEntryMappings(nftPostEntry)

	// Add an operation for the burnt NFT.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:          OperationTypeBurnNFT,
		PrevNFTEntry:  &prevNFTEntry,
		PrevPostEntry: &prevPostEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectCreateNFT(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreateNFT operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreateNFT: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreateNFT {
		return fmt.Errorf("_disconnectCreateNFT: Trying to revert "+
			"OperationTypeCreateNFT but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*CreateNFTMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_disconnectCreateNFT: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			txMeta.NFTPostHash.String())
	}

	// Revert to the old post entry since we changed IsNFT, etc.
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Delete the NFT entries.
	posterPKID := bav.GetPKIDForPublicKey(existingPostEntry.PosterPublicKey)
	if posterPKID == nil || posterPKID.isDeleted {
		return fmt.Errorf("_disconnectCreateNFT: PKID for poster public key %v doesn't exist; this should never happen", string(existingPostEntry.PosterPublicKey))
	}
	for ii := uint64(1); ii <= txMeta.NumCopies; ii++ {
		nftEntry := &NFTEntry{
			OwnerPKID:    posterPKID.PKID,
			NFTPostHash:  txMeta.NFTPostHash,
			SerialNumber: ii,
			IsForSale:    true,
		}
		bav._deleteNFTEntryMappings(nftEntry)
	}

	// Now revert the basic transfer with the remaining operations. Cut off
	// the CreatorCoin operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectUpdateNFT(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an UpdateNFT operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectUpdateNFT: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeUpdateNFT {
		return fmt.Errorf("_disconnectUpdateNFT: Trying to revert "+
			"OperationTypeUpdateNFT but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*UpdateNFTMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// In order to disconnect an updated NFT, we need to do the following:
	// 	(1) Revert the NFT entry to the previous one.
	//  (2) Add back all of the bids that were deleted (if any).
	//  (3) Revert the post entry since we updated num NFT copies for sale.

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectUpdateNFT: prev NFT entry doesn't exist; " +
			"this should never happen")
	}

	// If the previous NFT entry was not for sale, it should not have had any bids to delete.
	if !operationData.PrevNFTEntry.IsForSale &&
		operationData.DeletedNFTBidEntries != nil &&
		len(operationData.DeletedNFTBidEntries) > 0 {

		return fmt.Errorf("_disconnectUpdateNFT: prev NFT entry was not for sale but found " +
			"deleted bids anyway; this should never happen")
	}

	// Set the old NFT entry.
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Set the old bids.
	if operationData.DeletedNFTBidEntries != nil {
		for _, nftBid := range operationData.DeletedNFTBidEntries {
			bav._setNFTBidEntryMappings(nftBid)
		}
	}

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_disconnectUpdateNFT: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			txMeta.NFTPostHash.String())
	}

	// Revert to the old post entry since we changed NumNFTCopiesForSale.
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectAcceptNFTBid(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an AcceptNFTBid operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAcceptNFTBid {
		return fmt.Errorf("_disconnectAcceptNFTBid: Trying to revert "+
			"OperationTypeAcceptNFTBid but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*AcceptNFTBidMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// We sometimes have some extra AddUtxo operations we need to remove
	// These are "implicit" outputs that always occur at the end of the
	// list of UtxoOperations. The number of implicit outputs is equal to
	// the total number of "Add" operations minus the explicit outputs.
	numUtxoAdds := 0
	for _, utxoOp := range utxoOpsForTxn {
		if utxoOp.Type == OperationTypeAddUtxo {
			numUtxoAdds += 1
		}
	}
	if err := bav._helpDisconnectNFTSold(operationData, txMeta.NFTPostHash); err != nil {
		return errors.Wrapf(err, "_disconnectAcceptNFTBid: ")
	}

	// Now revert the basic transfer with the remaining operations.
	numBidderInputs := len(currentTxn.TxnMeta.(*AcceptNFTBidMetadata).BidderInputs)
	numNftOperations := (numUtxoAdds - len(currentTxn.TxOutputs) + numBidderInputs)
	operationIndex -= numNftOperations
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _helpDisconnectNFTSold(operationData *UtxoOperation, nftPostHash *BlockHash) error {
	// In order to disconnect the selling of an NFT, we need to do the following:

	// In order to disconnect an accepted bid, we need to do the following:
	// 	(1) Revert the NFT entry to the previous one with the previous owner.
	//  (2) Add back all of the bids that were deleted.
	//  (3) Disconnect payment UTXOs.
	//  (4) Unspend bidder UTXOs if this is not an NFT Bid type operation.
	//  (5) Revert profileEntry to undo royalties added to DeSoLockedNanos.
	//  (6) Revert the postEntry since NumNFTCopiesForSale was decremented.

	// (1) Set the old NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_helpDisconnectNFTSold: prev NFT entry doesn't exist; " +
			"this should never happen")
	}

	prevNFTEntry := operationData.PrevNFTEntry
	bav._setNFTEntryMappings(prevNFTEntry)

	// Revert the accepted NFT bid history mappings
	bav._setAcceptNFTBidHistoryMappings(MakeNFTKey(prevNFTEntry.NFTPostHash, prevNFTEntry.SerialNumber), operationData.PrevAcceptedNFTBidEntries)

	// (2) Set the old bids.
	if operationData.DeletedNFTBidEntries == nil || len(operationData.DeletedNFTBidEntries) == 0 {
		return fmt.Errorf("_helpDisconnectNFTSold: DeletedNFTBidEntries doesn't exist; " +
			"this should never happen")
	}

	for _, nftBid := range operationData.DeletedNFTBidEntries {
		bav._setNFTBidEntryMappings(nftBid)
	}

	// (3) Revert payments made from accepting the NFT bids.
	if operationData.NFTPaymentUtxoKeys == nil || len(operationData.NFTPaymentUtxoKeys) == 0 {
		return fmt.Errorf("_helpDisconnectNFTSold: NFTPaymentUtxoKeys was nil; " +
			"this should never happen")
	}
	// Note: these UTXOs need to be unadded in reverse order.
	// This unadds payment UTXOs for bidder change, creator royalties, seller profits, and additional DESO royalties.
	for ii := len(operationData.NFTPaymentUtxoKeys) - 1; ii >= 0; ii-- {
		paymentUtxoKey := operationData.NFTPaymentUtxoKeys[ii]
		if err := bav._unAddUtxo(paymentUtxoKey); err != nil {
			return errors.Wrapf(err, "_helpDisconnectNFTSold: Problem unAdding utxo %v: ", paymentUtxoKey)
		}
	}

	// We do not need to revert bidder UTXOs if this is an NFT Bid on a Buy Now NFT, because the bidder inputs are specified

	// (4) Revert spent bidder UTXOs.
	// as transaction inputs as opposed to bidder inputs that are specified in the transaction metadata since the transactor
	// and the bidder are the same in this scenario.
	if operationData.Type == OperationTypeAcceptNFTBid {
		// (4) Revert spent bidder UTXOs.
		if operationData.NFTSpentUtxoEntries == nil || len(operationData.NFTSpentUtxoEntries) == 0 {
			return fmt.Errorf("_helpDisconnectNFTSold: NFTSpentUtxoEntries was nil; " +
				"this should never happen")
		}

		// Note: these UTXOs need to be unspent in reverse order.
		for ii := len(operationData.NFTSpentUtxoEntries) - 1; ii >= 0; ii-- {
			spentUtxoEntry := operationData.NFTSpentUtxoEntries[ii]
			if err := bav._unSpendUtxo(spentUtxoEntry); err != nil {
				return errors.Wrapf(err, "_helpDisconnectNFTSold: Problem unSpending utxo %v: ", spentUtxoEntry)
			}
		}
	} else if operationData.Type == OperationTypeNFTBid {
		// Check that there are no NFTSpentUtxoEntries.
		if len(operationData.NFTSpentUtxoEntries) > 0 {
			return fmt.Errorf("_helpDisconnectNFTSold: NFT Bid operations should have zero NFTSpentUtxoEntries; " +
				"this should never happen")
		}
		// Check that the prevNFTEntry is a Buy Now NFT.
		if !prevNFTEntry.IsBuyNow {
			return fmt.Errorf("_helpDisconnectNFTSold: Previous NFT Entry is not buy now, " +
				"but operation is of type OperationTypeNFTBid; this should never happen")
		}
	} else {
		return fmt.Errorf("_helpDisconnectNFTSold: Invalid Operation type: %s", operationData.Type.String())
	}

	// (5) Revert the creator's CreatorCoinEntry if a previous one exists.
	if operationData.PrevCoinEntry != nil {
		nftPostEntry := bav.GetPostEntryForPostHash(operationData.PrevNFTEntry.NFTPostHash)
		// We have to get the post entry first so that we have the poster's pub key.
		if nftPostEntry == nil || nftPostEntry.isDeleted {
			return fmt.Errorf("_helpDisconnectNFTSold: nftPostEntry was nil; " +
				"this should never happen")
		}
		existingProfileEntry := bav.GetProfileEntryForPublicKey(nftPostEntry.PosterPublicKey)
		if existingProfileEntry == nil || existingProfileEntry.isDeleted {
			return fmt.Errorf("_helpDisconnectNFTSold: existingProfileEntry was nil; " +
				"this should never happen")
		}
		existingProfileEntry.CreatorCoinEntry = *operationData.PrevCoinEntry
		bav._setProfileEntryMappings(existingProfileEntry)
	}

	// (5-a) Revert the additional coin royalties CoinEntries if they exist.
	if operationData.PrevCoinRoyaltyCoinEntries != nil {
		for pkidIter, coinEntry := range operationData.PrevCoinRoyaltyCoinEntries {
			pkid := pkidIter
			profileEntry := bav.GetProfileEntryForPKID(&pkid)
			if profileEntry == nil || profileEntry.isDeleted {
				return errors.New("_helpDisconnectNFTSold: profile entry was nil or deleted for additional" +
					" coin royalty; this should never happen.")
			}
			profileEntry.CreatorCoinEntry = coinEntry
			bav._setProfileEntryMappings(profileEntry)
		}
	}

	// (6) Verify a postEntry exists and then revert it since NumNFTCopiesForSale was decremented.

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(nftPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_helpDisconnectNFTSold: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			nftPostHash.String())
	}

	// Revert to the old post entry since we changed NumNFTCopiesForSale.
	bav._setPostEntryMappings(operationData.PrevPostEntry)
	return nil
}

func (bav *UtxoView) _disconnectNFTBid(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a CreatorCoinTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectNFTBid: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeNFTBid {
		return fmt.Errorf("_disconnectNFTBid: Trying to revert "+
			"OperationTypeNFTBid but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*NFTBidMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// We sometimes have some extra AddUtxo operations we need to remove
	// These are "implicit" outputs that always occur at the end of the
	// list of UtxoOperations. The number of implicit outputs is equal to
	// the total number of "Add" operations minus the explicit outputs.
	numUtxoAdds := 0
	for _, utxoOp := range utxoOpsForTxn {
		if utxoOp.Type == OperationTypeAddUtxo {
			numUtxoAdds += 1
		}
	}
	operationIndex -= numUtxoAdds - len(currentTxn.TxOutputs)

	// Get the NFTBidEntry corresponding to this txn.
	bidderPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if bidderPKID == nil || bidderPKID.isDeleted {
		return fmt.Errorf("_disconnectNFTBid: PKID for bidder public key %v doesn't exist; this should never "+
			"happen", string(currentTxn.PublicKey))
	}

	// If an NFT Bid operation has a non-nil PrevNFTEntry, this was bid on a Buy-Now NFT and we need to "unsell" the NFT
	if operationData.PrevNFTEntry != nil {
		// If the previous NFT Entry is not a Buy Now NFT, that is an error. A bid on a non-buy-now NFT should never
		// manipulate an NFT Entry.
		if !operationData.PrevNFTEntry.IsBuyNow {
			return fmt.Errorf("_disconnectNFTBid: PrevNFTEntry is non-nil and is not Buy Now on NFT bid operation. This should never happen.")
		}

		// We now know that this was a bid on a buy-now NFT and the underlying NFT was sold outright to the bidder.
		// We go ahead an unsell the NFT.
		if err := bav._helpDisconnectNFTSold(operationData, txMeta.NFTPostHash); err != nil {
			return errors.Wrapf(err, "_disconnectNFTBid: ")
		}
	}

	// Now we can delete the NFT bid.
	nftBidKey := MakeNFTBidKey(bidderPKID.PKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	nftBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)

	// Only delete the bid entry mapping if it exists. Bids of 0 nanos delete bids without creating new ones.
	if nftBidEntry != nil {
		// We do not check if the existing entry is deleted or not. Because a bid amount of 0 cancels a bid (deletes
		// without creating one), if a user were to create a bid, cancel it, and create a new one, this disconnect logic
		// would encounter a state where the bid entry is delete.
		bav._deleteNFTBidEntryMappings(nftBidEntry)
	}

	// If a previous entry exists, set it.
	if operationData.PrevNFTBidEntry != nil {
		bav._setNFTBidEntryMappings(operationData.PrevNFTBidEntry)
	}

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectNFTTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an NFTTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectNFTTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeNFTTransfer {
		return fmt.Errorf("_disconnectNFTTransfer: Trying to revert "+
			"OperationTypeNFTTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*NFTTransferMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectNFTTransfer: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Sanity check the old NFT entry PKID / PostHash / SerialNumber.
	updaterPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return fmt.Errorf("_disconnectNFTTransfer: non-existent updaterPKID: %s",
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(operationData.PrevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return fmt.Errorf(
			"_disconnectNFTTransfer: updaterPKID does not match NFT owner: %s, %s",
			PkToString(updaterPKID.PKID[:], bav.Params),
			PkToString(operationData.PrevNFTEntry.OwnerPKID[:], bav.Params))
	}
	if !reflect.DeepEqual(txMeta.NFTPostHash, operationData.PrevNFTEntry.NFTPostHash) ||
		txMeta.SerialNumber != operationData.PrevNFTEntry.SerialNumber {
		return fmt.Errorf("_disconnectNFTTransfer: txMeta post hash and serial number do "+
			"not match previous NFT entry; this should never happen (%v, %v).",
			txMeta, operationData.PrevNFTEntry)
	}

	// Sanity check that the old NFT entry was not for sale.
	if operationData.PrevNFTEntry.IsForSale {
		return fmt.Errorf("_disconnecttNFTTransfer: prevNFT Entry was either not "+
			"pending or for sale (%v); this should never happen.", operationData.PrevNFTEntry)
	}

	// Get the current NFT entry so we can delete it.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	currNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if currNFTEntry == nil || currNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectNFTTransfer: currNFTEntry not found: %s, %d",
			txMeta.NFTPostHash.String(), txMeta.SerialNumber)
	}

	// Set the old NFT entry.
	bav._deleteNFTEntryMappings(currNFTEntry)
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectAcceptNFTTransfer(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an AcceptNFTTransfer operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAcceptNFTTransfer {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: Trying to revert "+
			"OperationTypeAcceptNFTTransfer but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*AcceptNFTTransferMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Sanity check the old NFT entry PKID / PostHash / SerialNumber.
	updaterPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: non-existent updaterPKID: %s",
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(operationData.PrevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return fmt.Errorf(
			"_disconnectAcceptNFTTransfer: updaterPKID does not match NFT owner: %s, %s",
			PkToString(updaterPKID.PKID[:], bav.Params),
			PkToString(operationData.PrevNFTEntry.OwnerPKID[:], bav.Params))
	}
	if !reflect.DeepEqual(txMeta.NFTPostHash, operationData.PrevNFTEntry.NFTPostHash) ||
		txMeta.SerialNumber != operationData.PrevNFTEntry.SerialNumber {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: txMeta post hash and serial number"+
			" do not match previous NFT entry; this should never happen (%v, %v).",
			txMeta, operationData.PrevNFTEntry)
	}

	// Sanity check that the old NFT entry was pending and not for sale.
	if !operationData.PrevNFTEntry.IsPending || operationData.PrevNFTEntry.IsForSale {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: prevNFT Entry was either not "+
			"pending or for sale (%v); this should never happen.", operationData.PrevNFTEntry)
	}

	// Get the current NFT entry so we can delete it.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	currNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if currNFTEntry == nil || currNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTTransfer: currNFTEntry not found: %s, %d",
			txMeta.NFTPostHash.String(), txMeta.SerialNumber)
	}

	// Delete the current NFT entry and set the old one.
	bav._deleteNFTEntryMappings(currNFTEntry)
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}

func (bav *UtxoView) _disconnectBurnNFT(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an BurnNFT operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectBurnNFT: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeBurnNFT {
		return fmt.Errorf("_disconnectBurnNFT: Trying to revert "+
			"OperationTypeBurnNFT but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	txMeta := currentTxn.TxnMeta.(*BurnNFTMetadata)
	operationData := utxoOpsForTxn[operationIndex]
	operationIndex--

	// Make sure that there is a prev NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Make sure that there is a prev post entry.
	if operationData.PrevPostEntry == nil || operationData.PrevPostEntry.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: prev NFT entry doesn't exist; " +
			"this should never happen.")
	}

	// Sanity check the old NFT entry PKID / PostHash / SerialNumber.
	updaterPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if updaterPKID == nil || updaterPKID.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: non-existent updaterPKID: %s",
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(operationData.PrevNFTEntry.OwnerPKID, updaterPKID.PKID) {
		return fmt.Errorf("_disconnectBurnNFT: updaterPKID does not match NFT owner: %s, %s",
			PkToString(updaterPKID.PKID[:], bav.Params),
			PkToString(operationData.PrevNFTEntry.OwnerPKID[:], bav.Params))
	}
	if !reflect.DeepEqual(txMeta.NFTPostHash, operationData.PrevNFTEntry.NFTPostHash) ||
		txMeta.SerialNumber != operationData.PrevNFTEntry.SerialNumber {
		return fmt.Errorf("_disconnectBurnNFT: txMeta post hash and serial number do "+
			"not match previous NFT entry; this should never happen (%v, %v).",
			txMeta, operationData.PrevNFTEntry)
	}

	// Sanity check that the old NFT entry was not for sale.
	if operationData.PrevNFTEntry.IsForSale {
		return fmt.Errorf("_disconnectBurnNFT: prevNFTEntry was for sale (%v); this should"+
			" never happen.", operationData.PrevNFTEntry)
	}

	// Get the postEntry for sanity checking / deletion later.
	currPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if currPostEntry == nil || currPostEntry.isDeleted {
		return fmt.Errorf(
			"_disconnectBurnNFT: non-existent nftPostEntry for NFTPostHash: %s",
			txMeta.NFTPostHash.String())
	}

	// Sanity check that the previous num NFT copies burned makes sense.
	if operationData.PrevPostEntry.NumNFTCopiesBurned != currPostEntry.NumNFTCopiesBurned-1 {
		return fmt.Errorf(
			"_disconnectBurnNFT: prevPostEntry has the wrong num NFT copies burned %d != %d-1",
			operationData.PrevPostEntry.NumNFTCopiesBurned, currPostEntry.NumNFTCopiesBurned)
	}

	// Sanity check that there is no current NFT entry.
	nftKey := MakeNFTKey(txMeta.NFTPostHash, txMeta.SerialNumber)
	currNFTEntry := bav.GetNFTEntryForNFTKey(&nftKey)
	if currNFTEntry != nil && !currNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectBurnNFT: found currNFTEntry for burned NFT: %s, %d",
			txMeta.NFTPostHash.String(), txMeta.SerialNumber)
	}

	// Set the old NFT entry (no need to delete first since there is no current entry).
	bav._setNFTEntryMappings(operationData.PrevNFTEntry)

	// Delete the current post entry and set the old one.
	bav._deletePostEntryMappings(currPostEntry)
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
}
