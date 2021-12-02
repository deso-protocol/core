package lib

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/pkg/errors"
	"reflect"
)

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
