package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
)

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
