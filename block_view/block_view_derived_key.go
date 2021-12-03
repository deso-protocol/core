package block_view

import (
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/deso-protocol/core/db"
	"github.com/deso-protocol/core/network"
	"github.com/deso-protocol/core/types"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) _connectAuthorizeDerivedKey(
	txn *network.MsgDeSoTxn, txHash *types.BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	if blockHeight < types.NFTTransferOrBurnAndDerivedKeysBlockHeight {
		return 0, 0, nil, types.RuleErrorDerivedKeyBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != network.TxnTypeAuthorizeDerivedKey {
		return 0, 0, nil, fmt.Errorf("_connectAuthorizeDerivedKey: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	txMeta := txn.TxnMeta.(*network.AuthorizeDerivedKeyMetadata)

	// Validate the operation type.
	if txMeta.OperationType != network.AuthorizeDerivedKeyOperationValid &&
		txMeta.OperationType != network.AuthorizeDerivedKeyOperationNotValid {
		return 0, 0, nil, fmt.Errorf("_connectAuthorizeDerivedKey: called with bad OperationType %s",
			txn.TxnMeta.GetTxnType().String())
	}

	// Make sure transaction hasn't expired.
	if txMeta.ExpirationBlock <= uint64(blockHeight) {
		return 0, 0, nil, types.RuleErrorAuthorizeDerivedKeyExpiredDerivedPublicKey
	}

	// Validate the owner public key.
	ownerPublicKey := txn.PublicKey
	if len(ownerPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, types.RuleErrorAuthorizeDerivedKeyInvalidOwnerPublicKey
	}
	if _, err := btcec.ParsePubKey(ownerPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(types.RuleErrorAuthorizeDerivedKeyInvalidOwnerPublicKey, err.Error())
	}

	// Validate the derived public key.
	derivedPublicKey := txMeta.DerivedPublicKey
	if len(derivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, types.RuleErrorAuthorizeDerivedKeyInvalidDerivedPublicKey
	}
	if _, err := btcec.ParsePubKey(derivedPublicKey, btcec.S256()); err != nil {
		return 0, 0, nil, errors.Wrap(types.RuleErrorAuthorizeDerivedKeyInvalidDerivedPublicKey, err.Error())
	}

	// Verify that the access signature is valid. This means the derived key is authorized.
	err := _verifyAccessSignature(ownerPublicKey, derivedPublicKey,
		txMeta.ExpirationBlock, txMeta.AccessSignature)
	if err != nil {
		return 0, 0, nil, errors.Wrap(types.RuleErrorAuthorizeDerivedKeyAccessSignatureNotValid, err.Error())
	}

	// Get current (previous) derived key entry. We might revert to it later so we copy it.
	prevDerivedKeyEntry := bav._getDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)

	// Authorize transactions can be signed by both owner and derived keys. However, this
	// poses a risk in a situation where a malicious derived key, which has previously been
	// de-authorized by the owner, were to attempt to re-authorize itself.
	// To prevent this, the following check completely blocks a derived key once it has been
	// de-authorized. This makes the lifecycle of a derived key more controllable.
	if prevDerivedKeyEntry != nil && !prevDerivedKeyEntry.isDeleted {
		if prevDerivedKeyEntry.OperationType == network.AuthorizeDerivedKeyOperationNotValid {
			return 0, 0, nil, types.RuleErrorAuthorizeDerivedKeyDeletedDerivedPublicKey
		}
	}

	// At this point we've verified the access signature, which means the derived key is authorized
	// to sign on behalf of the owner. In particular, if this authorize transaction was signed
	// by the derived key, we would accept it. We accommodate this by adding a temporary derived
	// key entry to UtxoView, to support first-time derived keys (they don't exist in the DB yet).
	// As a result, and if the derived key is present in transaction's ExtraData, we will
	// pass signature verification in _connectBasicTransfer() -> _verifySignature().
	//
	// NOTE: Setting a mapping in UtxoView prior to fully validating a transaction shouldn't be
	// reproduced elsewhere. It's error-prone, controversial, some even call it "a dirty hack!"
	// All considered, this feature greatly simplifies the flow in identity - from the moment you
	// generate a derived key, you can use it to sign any transaction offline, including authorize
	// transactions. It also resolves issues in situations where the owner account has insufficient
	// balance to submit an authorize transaction.
	derivedKeyEntry := DerivedKeyEntry{
		OwnerPublicKey:   *types.NewPublicKey(ownerPublicKey),
		DerivedPublicKey: *types.NewPublicKey(derivedPublicKey),
		ExpirationBlock:  txMeta.ExpirationBlock,
		OperationType:    network.AuthorizeDerivedKeyOperationValid,
		isDeleted:        false,
	}
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	// Call _connectBasicTransfer() to verify txn signature.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		// Since we've failed, we revert the UtxoView mapping to what it was previously.
		// We're doing this manually because we've set a temporary entry in UtxoView.
		bav._deleteDerivedKeyMapping(&derivedKeyEntry)
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return 0, 0, nil, errors.Wrapf(err, "_connectAuthorizeDerivedKey: ")
	}

	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		// Since we've failed, we revert the UtxoView mapping to what it was previously.
		// We're doing this manually because we've set a temporary entry in UtxoView.
		bav._deleteDerivedKeyMapping(&derivedKeyEntry)
		bav._setDerivedKeyMapping(prevDerivedKeyEntry)
		return 0, 0, nil, types.RuleErrorAuthorizeDerivedKeyRequiresNonZeroInput
	}

	// Earlier we've set a temporary derived key entry that had OperationType set to Valid.
	// So if the txn metadata had OperationType set to NotValid, we update the entry here.
	bav._deleteDerivedKeyMapping(&derivedKeyEntry)
	derivedKeyEntry.OperationType = txMeta.OperationType
	bav._setDerivedKeyMapping(&derivedKeyEntry)

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the owner key or the derived key.
	}

	// Add an operation to the list at the end indicating we've authorized a derived key.
	// Also add the prevDerivedKeyEntry for disconnecting.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                OperationTypeAuthorizeDerivedKey,
		PrevDerivedKeyEntry: prevDerivedKeyEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// _verifyAccessSignature verifies if the accessSignature is correct. Valid
// accessSignature is the signed hash of (derivedPublicKey + expirationBlock)
// in DER format, made with the ownerPublicKey.
func _verifyAccessSignature(ownerPublicKey []byte, derivedPublicKey []byte,
	expirationBlock uint64, accessSignature []byte) error {

	// Sanity-check and convert ownerPublicKey to *btcec.PublicKey.
	if len(ownerPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_verifyAccessSignature: Problem parsing owner public key")
	}
	ownerPk, err := btcec.ParsePubKey(ownerPublicKey, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing owner public key: ")
	}

	// Sanity-check and convert derivedPublicKey to *btcec.PublicKey.
	if len(derivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_verifyAccessSignature: Problem parsing derived public key")
	}
	_, err = btcec.ParsePubKey(derivedPublicKey, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing derived public key: ")
	}

	// Compute a hash of derivedPublicKey+expirationBlock.
	expirationBlockBytes := db.EncodeUint64(expirationBlock)
	accessBytes := append(derivedPublicKey, expirationBlockBytes[:]...)
	accessHash := types.Sha256DoubleHash(accessBytes)

	// Convert accessSignature to *btcec.Signature.
	signature, err := btcec.ParseDERSignature(accessSignature, btcec.S256())
	if err != nil {
		return errors.Wrapf(err, "_verifyAccessSignature: Problem parsing access signature: ")
	}

	// Verify signature.
	if !signature.Verify(accessHash[:], ownerPk) {
		return fmt.Errorf("_verifyAccessSignature: Invalid signature")
	}

	return nil
}

func (bav *UtxoView) _disconnectAuthorizeDerivedKey(
	operationType OperationType, currentTxn *network.MsgDeSoTxn, txnHash *types.BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a AuthorizeDerivedKey operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAuthorizeDerivedKey {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: Trying to revert "+
			"OperationTypeAuthorizeDerivedKey but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	txMeta := currentTxn.TxnMeta.(*network.AuthorizeDerivedKeyMetadata)
	prevDerivedKeyEntry := utxoOpsForTxn[operationIndex].PrevDerivedKeyEntry

	// Sanity check that txn public key is valid. Assign this public key to ownerPublicKey.
	var ownerPublicKey []byte
	if len(currentTxn.PublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid public key: %v", currentTxn.PublicKey)
	}
	_, err := btcec.ParsePubKey(currentTxn.PublicKey, btcec.S256())
	if err != nil {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid public key: %v", err)
	}
	ownerPublicKey = currentTxn.PublicKey

	// Sanity check that derived key is valid. Assign this key to derivedPublicKey.
	var derivedPublicKey []byte
	if len(txMeta.DerivedPublicKey) != btcec.PubKeyBytesLenCompressed {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid derived key: %v", txMeta.DerivedPublicKey)
	}
	_, err = btcec.ParsePubKey(txMeta.DerivedPublicKey, btcec.S256())
	if err != nil {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey invalid derived key: %v", err)
	}
	derivedPublicKey = txMeta.DerivedPublicKey

	// Get the derived key entry. If it's nil or is deleted then we have an error.
	derivedKeyEntry := bav._getDerivedKeyMappingForOwner(ownerPublicKey, derivedPublicKey)
	if derivedKeyEntry == nil || derivedKeyEntry.isDeleted {
		return fmt.Errorf("_disconnectAuthorizeDerivedKey: DerivedKeyEntry for "+
			"public key %v, derived key %v was found to be nil or deleted: %v",
			types.PkToString(ownerPublicKey, bav.Params), types.PkToString(derivedPublicKey, bav.Params),
			derivedKeyEntry)
	}

	// If we had a previous derivedKeyEntry set then compare it with the current entry.
	if prevDerivedKeyEntry != nil {
		// Sanity check public keys. This should never fail.
		if !reflect.DeepEqual(ownerPublicKey, prevDerivedKeyEntry.OwnerPublicKey[:]) {
			return fmt.Errorf("_disconnectAuthorizeDerivedKey: Owner public key in txn "+
				"differs from that in previous derivedKeyEntry (%v %v)", prevDerivedKeyEntry.OwnerPublicKey, ownerPublicKey)
		}
		if !reflect.DeepEqual(derivedPublicKey, prevDerivedKeyEntry.DerivedPublicKey[:]) {
			return fmt.Errorf("_disconnectAuthorizeDerivedKey: Derived public key in txn "+
				"differs from that in existing derivedKeyEntry (%v %v)", prevDerivedKeyEntry.DerivedPublicKey, derivedPublicKey)
		}
	}

	// Now that we are confident the derivedKeyEntry lines up with the transaction we're
	// rolling back, delete the mapping from utxoView. We need to do this to prevent
	// a fetch from a db later on.
	bav._deleteDerivedKeyMapping(derivedKeyEntry)

	// Set the previous derivedKeyEntry.
	bav._setDerivedKeyMapping(prevDerivedKeyEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the authorizeDerivedKey operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

// _getDerivedKeyMappingForOwner fetches the derived key mapping from the utxoView
func (bav *UtxoView) _getDerivedKeyMappingForOwner(ownerPublicKey []byte, derivedPublicKey []byte) *DerivedKeyEntry {
	// Check if the entry exists in utxoView.
	ownerPk := types.NewPublicKey(ownerPublicKey)
	derivedPk := types.NewPublicKey(derivedPublicKey)
	derivedKeyMapKey := MakeDerivedKeyMapKey(*ownerPk, *derivedPk)
	entry, exists := bav.DerivedKeyToDerivedEntry[derivedKeyMapKey]
	if exists {
		return entry
	}

	// Check if the entry exists in the DB.
	if bav.Postgres != nil {
		if entryPG := bav.Postgres.GetDerivedKey(ownerPk, derivedPk); entryPG != nil {
			entry = entryPG.NewDerivedKeyEntry()
		} else {
			entry = nil
		}
	} else {
		entry = db.DBGetOwnerToDerivedKeyMapping(bav.Handle, *ownerPk, *derivedPk)
	}

	// If an entry exists, update the UtxoView map.
	if entry != nil {
		bav._setDerivedKeyMapping(entry)
		return entry
	}
	return nil
}

// GetAllDerivedKeyMappingsForOwner fetches all derived key mappings belonging to an owner.
func (bav *UtxoView) GetAllDerivedKeyMappingsForOwner(ownerPublicKey []byte) (
	map[types.PublicKey]*DerivedKeyEntry, error) {
	derivedKeyMappings := make(map[types.PublicKey]*DerivedKeyEntry)

	// Check for entries in UtxoView.
	for entryKey, entry := range bav.DerivedKeyToDerivedEntry {
		if reflect.DeepEqual(entryKey.OwnerPublicKey[:], ownerPublicKey) {
			derivedKeyMappings[entryKey.DerivedPublicKey] = entry
		}
	}

	// Check for entries in DB.
	var dbMappings []*DerivedKeyEntry
	ownerPk := types.NewPublicKey(ownerPublicKey)
	if bav.Postgres != nil {
		pgMappings := bav.Postgres.GetAllDerivedKeysForOwner(ownerPk)
		for _, entry := range pgMappings {
			dbMappings = append(dbMappings, entry.NewDerivedKeyEntry())
		}
	} else {
		var err error
		dbMappings, err = db.DBGetAllOwnerToDerivedKeyMappings(bav.Handle, *ownerPk)
		if err != nil {
			return nil, errors.Wrapf(err, "GetAllDerivedKeyMappingsForOwner: problem looking up"+
				"entries in the DB.")
		}
	}

	// Add entries from the DB that aren't already present.
	for _, entry := range dbMappings {
		mapKey := entry.DerivedPublicKey
		if _, ok := derivedKeyMappings[mapKey]; !ok {
			derivedKeyMappings[mapKey] = entry
		}
	}

	// Delete entries with isDeleted=true. We are deleting these entries
	// only now, because we wanted to skip corresponding keys in DB fetch.
	for entryKey, entry := range derivedKeyMappings {
		if entry.isDeleted {
			delete(derivedKeyMappings, entryKey)
		}
	}

	return derivedKeyMappings, nil
}

// _setDerivedKeyMapping sets a derived key mapping in the utxoView.
func (bav *UtxoView) _setDerivedKeyMapping(derivedKeyEntry *DerivedKeyEntry) {
	// If the derivedKeyEntry is nil then there's nothing to do.
	if derivedKeyEntry == nil {
		return
	}
	// Add a mapping for the derived key.
	derivedKeyMapKey := MakeDerivedKeyMapKey(derivedKeyEntry.OwnerPublicKey, derivedKeyEntry.DerivedPublicKey)
	bav.DerivedKeyToDerivedEntry[derivedKeyMapKey] = derivedKeyEntry
}

// _deleteDerivedKeyMapping deletes a derived key mapping from utxoView.
func (bav *UtxoView) _deleteDerivedKeyMapping(derivedKeyEntry *DerivedKeyEntry) {
	// If the derivedKeyEntry is nil then there's nothing to do.
	if derivedKeyEntry == nil {
		return
	}

	// Create a tombstone entry.
	tombstoneDerivedKeyEntry := *derivedKeyEntry
	tombstoneDerivedKeyEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setDerivedKeyMapping(&tombstoneDerivedKeyEntry)
}
