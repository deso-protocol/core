package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
)

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
