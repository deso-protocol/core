package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"math/big"
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

	// Validate the txMeta.
	if txMeta.NumCopies > bav.GlobalParamsEntry.MaxCopiesPerNFT {
		return 0, 0, nil, RuleErrorTooManyNFTCopies
	}
	if txMeta.NumCopies == 0 {
		return 0, 0, nil, RuleErrorNFTMustHaveNonZeroCopies
	}
	// Make sure we won't oveflow when we add the royalty basis points.
	if math.MaxUint64-txMeta.NFTRoyaltyToCreatorBasisPoints < txMeta.NFTRoyaltyToCoinBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyOverflow
	}
	royaltyBasisPoints := txMeta.NFTRoyaltyToCreatorBasisPoints + txMeta.NFTRoyaltyToCoinBasisPoints
	if royaltyBasisPoints > bav.Params.MaxNFTRoyaltyBasisPoints {
		return 0, 0, nil, RuleErrorNFTRoyaltyHasTooManyBasisPoints
	}
	postEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	if postEntry == nil || postEntry.isDeleted {
		return 0, 0, nil, RuleErrorCreateNFTOnNonexistentPost
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
	bav._setPostEntryMappings(postEntry)

	posterPKID := bav.GetPKIDForPublicKey(postEntry.PosterPublicKey)
	if posterPKID == nil || posterPKID.isDeleted {
		return 0, 0, nil, fmt.Errorf("_connectCreateNFT: non-existent posterPKID: %s",
			PkToString(postEntry.PosterPublicKey, bav.Params))
	}

	// Add the appropriate NFT entries.
	for ii := uint64(1); ii <= txMeta.NumCopies; ii++ {
		nftEntry := &NFTEntry{
			OwnerPKID:         posterPKID.PKID,
			NFTPostHash:       txMeta.NFTPostHash,
			SerialNumber:      ii,
			IsForSale:         txMeta.IsForSale,
			MinBidAmountNanos: txMeta.MinBidAmountNanos,
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
		// Keep the last accepted bid amount nanos from the previous entry since this
		// value is only updated when a new bid is accepted.
		LastAcceptedBidAmountNanos: prevNFTEntry.LastAcceptedBidAmountNanos,
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

	// Get the poster's profile.
	existingProfileEntry := bav.GetProfileEntryForPublicKey(nftPostEntry.PosterPublicKey)
	if existingProfileEntry == nil || existingProfileEntry.isDeleted {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Profile missing for NFT pub key: %v %v",
			PkToStringMainnet(nftPostEntry.PosterPublicKey), PkToStringTestnet(nftPostEntry.PosterPublicKey))
	}
	// Save all the old values from the CoinEntry before we potentially
	// update them. Note that CoinEntry doesn't contain any pointers and so
	// a direct copy is OK.
	prevCoinEntry := existingProfileEntry.CoinEntry

	// Verify the NFT bid entry being accepted exists and has a bid consistent with the metadata.
	// If we did not require an AcceptNFTBid txn to have a bid amount, it would leave the door
	// open for an attack where someone replaces a high bid with a low bid after the owner accepts.
	nftBidKey := MakeNFTBidKey(txMeta.BidderPKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	nftBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	if nftBidEntry == nil || nftBidEntry.isDeleted {
		// NOTE: Users can submit a bid for SerialNumber zero as a blanket bid for any SerialNumber
		// in an NFT collection. Thus, we must check to see if a SerialNumber zero bid exists
		// for this bidder before we return an error.
		nftBidKey = MakeNFTBidKey(txMeta.BidderPKID, txMeta.NFTPostHash, uint64(0))
		nftBidEntry = bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
		if nftBidEntry == nil || nftBidEntry.isDeleted {
			return 0, 0, nil, RuleErrorCantAcceptNonExistentBid
		}
	}
	if nftBidEntry.BidAmountNanos != txMeta.BidAmountNanos {
		return 0, 0, nil, RuleErrorAcceptedNFTBidAmountDoesNotMatch
	}

	bidderPublicKey := bav.GetPublicKeyForPKID(txMeta.BidderPKID)

	//
	// Store starting balances of all the participants to check diff later.
	//
	// We assume the tip is right before the block in which this txn is about to be applied.
	tipHeight := uint32(0)
	if blockHeight > 0 {
		tipHeight = blockHeight - 1
	}
	sellerBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting initial balance for seller pubkey: %v",
			PkToStringBoth(txn.PublicKey))
	}
	bidderBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(
		bidderPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting initial balance for bidder pubkey: %v",
			PkToStringBoth(bidderPublicKey))
	}
	creatorBalanceBefore, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(
		nftPostEntry.PosterPublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting initial balance for poster pubkey: %v",
			PkToStringBoth(nftPostEntry.PosterPublicKey))
	}

	//
	// Validate bidder UTXOs.
	//
	if len(txMeta.BidderInputs) == 0 {
		return 0, 0, nil, RuleErrorAcceptedNFTBidMustSpecifyBidderInputs
	}
	totalBidderInput := uint64(0)
	spentUtxoEntries := []*UtxoEntry{}
	utxoOpsForTxn := []*UtxoOperation{}
	for _, bidderInput := range txMeta.BidderInputs {
		bidderUtxoKey := UtxoKey(*bidderInput)
		bidderUtxoEntry := bav.GetUtxoEntryForUtxoKey(&bidderUtxoKey)
		if bidderUtxoEntry == nil || bidderUtxoEntry.isSpent {
			return 0, 0, nil, RuleErrorBidderInputForAcceptedNFTBidNoLongerExists
		}

		// Make sure that the utxo specified is actually from the bidder.
		if !reflect.DeepEqual(bidderUtxoEntry.PublicKey, bidderPublicKey) {
			return 0, 0, nil, RuleErrorInputWithPublicKeyDifferentFromTxnPublicKey
		}

		// If the utxo is from a block reward txn, make sure enough time has passed to
		// make it spendable.
		if _isEntryImmatureBlockReward(bidderUtxoEntry, blockHeight, bav.Params) {
			return 0, 0, nil, RuleErrorInputSpendsImmatureBlockReward
		}
		totalBidderInput += bidderUtxoEntry.AmountNanos

		// Make sure we spend the utxo so that the bidder can't reuse it.
		utxoOp, err := bav._spendUtxo(&bidderUtxoKey)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: Problem spending bidder utxo")
		}
		spentUtxoEntries = append(spentUtxoEntries, bidderUtxoEntry)

		// Track the UtxoOperations so we can rollback, and for Rosetta
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	if totalBidderInput < txMeta.BidAmountNanos {
		return 0, 0, nil, RuleErrorAcceptNFTBidderInputsInsufficientForBidAmount
	}

	// The bidder gets back any unspent nanos from the inputs specified.
	bidderChangeNanos := totalBidderInput - txMeta.BidAmountNanos
	// The amount of deso that should go to the original creator from this purchase.
	// Calculated as: (BidAmountNanos * NFTRoyaltyToCreatorBasisPoints) / (100 * 100)
	creatorRoyaltyNanos := IntDiv(
		IntMul(
			big.NewInt(int64(txMeta.BidAmountNanos)),
			big.NewInt(int64(nftPostEntry.NFTRoyaltyToCreatorBasisPoints))),
		big.NewInt(100*100)).Uint64()
	// The amount of deso that should go to the original creator's coin from this purchase.
	// Calculated as: (BidAmountNanos * NFTRoyaltyToCoinBasisPoints) / (100 * 100)
	creatorCoinRoyaltyNanos := IntDiv(
		IntMul(
			big.NewInt(int64(txMeta.BidAmountNanos)),
			big.NewInt(int64(nftPostEntry.NFTRoyaltyToCoinBasisPoints))),
		big.NewInt(100*100)).Uint64()
	//glog.Infof("Bid amount: %d, coin basis points: %d, coin royalty: %d",
	//	txMeta.BidAmountNanos, nftPostEntry.NFTRoyaltyToCoinBasisPoints, creatorCoinRoyaltyNanos)

	// Sanity check that the royalties are reasonable and won't cause underflow.
	if txMeta.BidAmountNanos < (creatorRoyaltyNanos + creatorCoinRoyaltyNanos) {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: sum of royalties (%d, %d) is less than bid amount (%d)",
			creatorRoyaltyNanos, creatorCoinRoyaltyNanos, txMeta.BidAmountNanos)
	}

	bidAmountMinusRoyalties := txMeta.BidAmountNanos - creatorRoyaltyNanos - creatorCoinRoyaltyNanos

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsFromBasicTransfer, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: ")
	}
	// Append the basic transfer utxoOps to our list
	utxoOpsForTxn = append(utxoOpsForTxn, utxoOpsFromBasicTransfer...)

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorAcceptNFTBidRequiresNonZeroInput
	}

	if verifySignatures {
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
		LastOwnerPKID:  updaterPKID.PKID,
		OwnerPKID:      txMeta.BidderPKID,
		NFTPostHash:    txMeta.NFTPostHash,
		SerialNumber:   txMeta.SerialNumber,
		IsForSale:      false,
		UnlockableText: txMeta.UnlockableText,

		LastAcceptedBidAmountNanos: txMeta.BidAmountNanos,
	}
	bav._setNFTEntryMappings(newNFTEntry)

	// append the accepted bid entry to the list of accepted bid entries
	prevAcceptedBidHistory := bav.GetAcceptNFTBidHistoryForNFTKey(&nftKey)
	newAcceptedBidHistory := append(*prevAcceptedBidHistory, nftBidEntry)
	bav._setAcceptNFTBidHistoryMappings(nftKey, &newAcceptedBidHistory)

	// (2) Iterate over all the NFTBidEntries for this NFT and delete them.
	bidEntries := bav.GetAllNFTBidEntries(txMeta.NFTPostHash, txMeta.SerialNumber)
	if len(bidEntries) == 0 && nftBidEntry.SerialNumber != 0 {
		// Quick sanity check to make sure that we found bid entries. There should be at least 1.
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: found zero bid entries to delete; this should never happen.")
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

	// (3) Pay the seller by creating a new entry for this output and add it to the view.
	nftPaymentUtxoKeys := []*UtxoKey{}
	nextUtxoIndex := uint32(len(txn.TxOutputs))
	sellerOutputKey := &UtxoKey{
		TxID:  *txHash,
		Index: nextUtxoIndex,
	}

	utxoEntry := UtxoEntry{
		AmountNanos: bidAmountMinusRoyalties,
		PublicKey:   txn.PublicKey,
		BlockHeight: blockHeight,
		UtxoType:    UtxoTypeNFTSeller,
		UtxoKey:     sellerOutputKey,
		// We leave the position unset and isSpent to false by default.
		// The position will be set in the call to _addUtxo.
	}

	// Create a new scope to avoid name collisions
	{
		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(
				err, "_connectAcceptNFTBid: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, sellerOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	// (4) Pay royalties to the original artist.
	if creatorRoyaltyNanos > 0 {
		nextUtxoIndex += 1
		royaltyOutputKey := &UtxoKey{
			TxID:  *txHash,
			Index: nextUtxoIndex,
		}

		utxoEntry := UtxoEntry{
			AmountNanos: creatorRoyaltyNanos,
			PublicKey:   nftPostEntry.PosterPublicKey,
			BlockHeight: blockHeight,
			UtxoType:    UtxoTypeNFTCreatorRoyalty,

			UtxoKey: royaltyOutputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}

		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, royaltyOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	// (5) Give any change back to the bidder.
	if bidderChangeNanos > 0 {
		nextUtxoIndex += 1
		bidderChangeOutputKey := &UtxoKey{
			TxID:  *txHash,
			Index: nextUtxoIndex,
		}

		utxoEntry := UtxoEntry{
			AmountNanos: bidderChangeNanos,
			PublicKey:   bidderPublicKey,
			BlockHeight: blockHeight,
			UtxoType:    UtxoTypeNFTCreatorRoyalty,

			UtxoKey: bidderChangeOutputKey,
			// We leave the position unset and isSpent to false by default.
			// The position will be set in the call to _addUtxo.
		}

		utxoOp, err := bav._addUtxo(&utxoEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAcceptNFTBid: Problem adding output utxo")
		}
		nftPaymentUtxoKeys = append(nftPaymentUtxoKeys, bidderChangeOutputKey)

		// Rosetta uses this UtxoOperation to provide INPUT amounts
		utxoOpsForTxn = append(utxoOpsForTxn, utxoOp)
	}

	// We don't do a royalty if the number of coins in circulation is too low.
	if existingProfileEntry.CoinsInCirculationNanos < bav.Params.CreatorCoinAutoSellThresholdNanos {
		creatorCoinRoyaltyNanos = 0
	}

	// (6) Add creator coin royalties to deso locked. If the number of coins in circulation is
	// less than the "auto sell threshold" we burn the deso.
	newCoinEntry := prevCoinEntry
	if creatorCoinRoyaltyNanos > 0 {
		// Make a copy of the previous coin entry. It has no pointers, so a direct copy is ok.
		newCoinEntry.DeSoLockedNanos += creatorCoinRoyaltyNanos
		existingProfileEntry.CoinEntry = newCoinEntry
		bav._setProfileEntryMappings(existingProfileEntry)
	}

	// (7) Save a copy of the previous postEntry and then decrement NumNFTCopiesForSale.
	prevPostEntry := &PostEntry{}
	*prevPostEntry = *nftPostEntry
	nftPostEntry.NumNFTCopiesForSale--
	bav._setPostEntryMappings(nftPostEntry)

	// Add an operation to the list at the end indicating we've connected an NFT bid.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                      OperationTypeAcceptNFTBid,
		PrevNFTEntry:              prevNFTEntry,
		PrevPostEntry:             prevPostEntry,
		PrevCoinEntry:             &prevCoinEntry,
		DeletedNFTBidEntries:      deletedBidEntries,
		NFTPaymentUtxoKeys:        nftPaymentUtxoKeys,
		NFTSpentUtxoEntries:       spentUtxoEntries,
		PrevAcceptedNFTBidEntries: prevAcceptedBidHistory,

		// Rosetta fields.
		AcceptNFTBidCreatorPublicKey:    nftPostEntry.PosterPublicKey,
		AcceptNFTBidBidderPublicKey:     bidderPublicKey,
		AcceptNFTBidCreatorRoyaltyNanos: creatorCoinRoyaltyNanos,
	})

	// HARDCORE SANITY CHECK:
	//  - Before returning we do one more sanity check that money hasn't been printed.
	//
	// Seller balance diff:
	sellerBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(txn.PublicKey, tipHeight)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Problem getting final balance for seller pubkey: %v",
			PkToStringBoth(txn.PublicKey))
	}
	sellerDiff := int64(sellerBalanceAfter) - int64(sellerBalanceBefore)
	// Bidder balance diff (only relevant if bidder != seller):
	bidderDiff := int64(0)
	if !reflect.DeepEqual(bidderPublicKey, txn.PublicKey) {
		bidderBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(bidderPublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_connectAcceptNFTBid: Problem getting final balance for bidder pubkey: %v",
				PkToStringBoth(bidderPublicKey))
		}
		bidderDiff = int64(bidderBalanceAfter) - int64(bidderBalanceBefore)
	}
	// Creator balance diff (only relevant if creator != seller and creator != bidder):
	creatorDiff := int64(0)
	if !reflect.DeepEqual(nftPostEntry.PosterPublicKey, txn.PublicKey) &&
		!reflect.DeepEqual(nftPostEntry.PosterPublicKey, bidderPublicKey) {
		creatorBalanceAfter, err := bav.GetSpendableDeSoBalanceNanosForPublicKey(nftPostEntry.PosterPublicKey, tipHeight)
		if err != nil {
			return 0, 0, nil, fmt.Errorf(
				"_connectAcceptNFTBid: Problem getting final balance for poster pubkey: %v",
				PkToStringBoth(nftPostEntry.PosterPublicKey))
		}
		creatorDiff = int64(creatorBalanceAfter) - int64(creatorBalanceBefore)
	}
	// Creator coin diff:
	coinDiff := int64(newCoinEntry.DeSoLockedNanos) - int64(prevCoinEntry.DeSoLockedNanos)
	// Now the actual check. Use bigints to avoid getting fooled by overflow.
	sellerPlusBidderDiff := big.NewInt(0).Add(big.NewInt(sellerDiff), big.NewInt(bidderDiff))
	creatorPlusCoinDiff := big.NewInt(0).Add(big.NewInt(creatorDiff), big.NewInt(coinDiff))
	totalDiff := big.NewInt(0).Add(sellerPlusBidderDiff, creatorPlusCoinDiff)
	if totalDiff.Cmp(big.NewInt(0)) > 0 {
		return 0, 0, nil, fmt.Errorf(
			"_connectAcceptNFTBid: Sum of participant diffs is >0 (%d, %d, %d, %d)",
			sellerDiff, bidderDiff, creatorDiff, coinDiff)
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
		return 0, 0, nil, fmt.Errorf("_connectNFTBid: PKID for bidder public key %v doesn't exist; this should never happen", string(txn.PublicKey))
	}

	// Save a copy of the bid entry so that we can use it in the disconnect.
	nftBidKey := MakeNFTBidKey(bidderPKID.PKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	prevNFTBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)

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
	}

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

	} else if txMeta.BidAmountNanos > spendableBalance && blockHeight > BrokenNFTBidsFixBlockHeight {
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

	// Add an operation to the list at the end indicating we've connected an NFT bid.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:            OperationTypeNFTBid,
		PrevNFTBidEntry: prevNFTBidEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectNFTTransfer(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
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

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
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

	if blockHeight < NFTTransferOrBurnAndDerivedKeysBlockHeight {
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

	// Verify that the last operation is a CreatorCoinTransfer operation
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
	operationIndex -= numUtxoAdds - len(currentTxn.TxOutputs)

	// In order to disconnect an accepted bid, we need to do the following:
	// 	(1) Revert the NFT entry to the previous one with the previous owner.
	//  (2) Add back all of the bids that were deleted.
	//  (3) Disconnect payment UTXOs.
	//  (4) Unspend bidder UTXOs.
	//  (5) Revert profileEntry to undo royalties added to DeSoLockedNanos.
	//  (6) Revert the postEntry since NumNFTCopiesForSale was decremented.

	// (1) Set the old NFT entry.
	if operationData.PrevNFTEntry == nil || operationData.PrevNFTEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTBid: prev NFT entry doesn't exist; " +
			"this should never happen")
	}

	prevNFTEntry := operationData.PrevNFTEntry
	bav._setNFTEntryMappings(prevNFTEntry)

	// Revert the accepted NFT bid history mappings
	bav._setAcceptNFTBidHistoryMappings(MakeNFTKey(prevNFTEntry.NFTPostHash, prevNFTEntry.SerialNumber), operationData.PrevAcceptedNFTBidEntries)

	// (2) Set the old bids.
	if operationData.DeletedNFTBidEntries == nil || len(operationData.DeletedNFTBidEntries) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: DeletedNFTBidEntries doesn't exist; " +
			"this should never happen")
	}

	for _, nftBid := range operationData.DeletedNFTBidEntries {
		bav._setNFTBidEntryMappings(nftBid)
	}

	// (3) Revert payments made from accepting the NFT bids.
	if operationData.NFTPaymentUtxoKeys == nil || len(operationData.NFTPaymentUtxoKeys) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: NFTPaymentUtxoKeys was nil; " +
			"this should never happen")
	}
	// Note: these UTXOs need to be unadded in reverse order.
	for ii := len(operationData.NFTPaymentUtxoKeys) - 1; ii >= 0; ii-- {
		paymentUtxoKey := operationData.NFTPaymentUtxoKeys[ii]
		if err := bav._unAddUtxo(paymentUtxoKey); err != nil {
			return errors.Wrapf(err, "_disconnectAcceptNFTBid: Problem unAdding utxo %v: ", paymentUtxoKey)
		}
	}

	// (4) Revert spent bidder UTXOs.
	if operationData.NFTSpentUtxoEntries == nil || len(operationData.NFTSpentUtxoEntries) == 0 {
		return fmt.Errorf("_disconnectAcceptNFTBid: NFTSpentUtxoEntries was nil; " +
			"this should never happen")
	}
	// Note: these UTXOs need to be unspent in reverse order.
	for ii := len(operationData.NFTSpentUtxoEntries) - 1; ii >= 0; ii-- {
		spentUtxoEntry := operationData.NFTSpentUtxoEntries[ii]
		if err := bav._unSpendUtxo(spentUtxoEntry); err != nil {
			return errors.Wrapf(err, "_disconnectAcceptNFTBid: Problem unSpending utxo %v: ", spentUtxoEntry)
		}
	}

	// (5) Revert the creator's CoinEntry if a previous one exists.
	if operationData.PrevCoinEntry != nil {
		nftPostEntry := bav.GetPostEntryForPostHash(operationData.PrevNFTEntry.NFTPostHash)
		// We have to get the post entry first so that we have the poster's pub key.
		if nftPostEntry == nil || nftPostEntry.isDeleted {
			return fmt.Errorf("_disconnectAcceptNFTBid: nftPostEntry was nil; " +
				"this should never happen")
		}
		existingProfileEntry := bav.GetProfileEntryForPublicKey(nftPostEntry.PosterPublicKey)
		if existingProfileEntry == nil || existingProfileEntry.isDeleted {
			return fmt.Errorf("_disconnectAcceptNFTBid: existingProfileEntry was nil; " +
				"this should never happen")
		}
		existingProfileEntry.CoinEntry = *operationData.PrevCoinEntry
		bav._setProfileEntryMappings(existingProfileEntry)
	}

	// (6) Verify a postEntry exists and then revert it since NumNFTCopiesForSale was decremented.

	// Get the postEntry corresponding to this txn.
	existingPostEntry := bav.GetPostEntryForPostHash(txMeta.NFTPostHash)
	// Sanity-check that it exists.
	if existingPostEntry == nil || existingPostEntry.isDeleted {
		return fmt.Errorf("_disconnectAcceptNFTBid: Post entry for "+
			"post hash %v doesn't exist; this should never happen",
			txMeta.NFTPostHash.String())
	}

	// Revert to the old post entry since we changed NumNFTCopiesForSale.
	bav._setPostEntryMappings(operationData.PrevPostEntry)

	// Now revert the basic transfer with the remaining operations.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex+1], blockHeight)
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

	// Get the NFTBidEntry corresponding to this txn.
	bidderPKID := bav.GetPKIDForPublicKey(currentTxn.PublicKey)
	if bidderPKID == nil || bidderPKID.isDeleted {
		return fmt.Errorf("_disconnectNFTBid: PKID for bidder public key %v doesn't exist; this should never happen", string(currentTxn.PublicKey))
	}
	nftBidKey := MakeNFTBidKey(bidderPKID.PKID, txMeta.NFTPostHash, txMeta.SerialNumber)
	nftBidEntry := bav.GetNFTBidEntryForNFTBidKey(&nftBidKey)
	// Sanity-check that it exists.
	if nftBidEntry == nil || nftBidEntry.isDeleted {
		return fmt.Errorf("_disconnectNFTBid: Bid entry for "+
			"nftBidKey %v doesn't exist; this should never happen", nftBidKey)
	}

	// Delete the existing NFT bid entry.
	bav._deleteNFTBidEntryMappings(nftBidEntry)

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
