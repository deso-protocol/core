package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"math"
	"reflect"
)

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
