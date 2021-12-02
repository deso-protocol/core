package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"math/big"
	"reflect"
)

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
