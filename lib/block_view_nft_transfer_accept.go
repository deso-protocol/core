package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
)

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
