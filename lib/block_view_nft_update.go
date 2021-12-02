package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
)

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
