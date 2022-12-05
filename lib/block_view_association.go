package lib

import (
	"fmt"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"strings"
)

const MaxAssociationTypeCharLength int = 64
const MaxAssociationValueCharLength int = 256
const AssociationTypeReservedPrefix = "DESO"

func (bav *UtxoView) _connectCreateUserAssociation(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (
	_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error,
) {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreateUserAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectCreateUserAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreateUserAssociation: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CreateUserAssociationMetadata)

	// Validate the txn metadata.
	if err := bav.IsValidCreateUserAssociationMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, err
	}

	// At this point, we can assume the metadata is valid: all
	// PKIDs exist, strings are of an appropriate length, etc.

	// Check if there is an existing matching association entry that will be overwritten.
	// This existing association entry will be restored if we disconnect this txn.
	prevAssociationEntry, err := bav.GetUserAssociationByAttributes(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreateUserAssociation: ")
	}
	// Delete the existing association entry, if exists.
	if prevAssociationEntry != nil {
		bav._deleteUserAssociationEntryMappings(prevAssociationEntry)
	}

	// Construct new association entry from metadata.
	currentAssociationEntry := &UserAssociationEntry{
		AssociationID:    txHash,
		TransactorPKID:   bav.GetPKIDForPublicKey(txn.PublicKey).PKID,
		TargetUserPKID:   bav.GetPKIDForPublicKey(txMeta.TargetUserPublicKey.ToBytes()).PKID,
		AppUserPKID:      bav._associationAppUserPublicKeyToPKID(txMeta.AppUserPublicKey),
		AssociationType:  txMeta.AssociationType,
		AssociationValue: txMeta.AssociationValue,
		BlockHeight:      blockHeight,
	}
	// Create the association.
	bav._setUserAssociationEntryMappings(currentAssociationEntry)

	// Add a UTXO operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeCreateUserAssociation,
		PrevUserAssociationEntry: prevAssociationEntry,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectDeleteUserAssociation(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (
	_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error,
) {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDeleteUserAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeleteUserAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectDeleteUserAssociation: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*DeleteUserAssociationMetadata)

	// Validate the txn metadata.
	if err := bav.IsValidDeleteUserAssociationMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, err
	}

	// At this point, we can assume the metadata is valid: the
	// association ID is non-null and the association entry exists.

	// Delete the association.
	prevAssociationEntry, err := bav.GetUserAssociationByID(txMeta.AssociationID)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeleteUserAssociation: error fetching association %s", txMeta.AssociationID.String(),
		)
	}
	bav._deleteUserAssociationEntryMappings(prevAssociationEntry)

	// Add a UTXO operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeDeleteUserAssociation,
		PrevUserAssociationEntry: prevAssociationEntry,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectCreatePostAssociation(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (
	_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error,
) {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreatePostAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectCreatePostAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreatePostAssociation: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CreatePostAssociationMetadata)

	// Validate the txn metadata.
	if err := bav.IsValidCreatePostAssociationMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, err
	}

	// At this point, we can assume the metadata is valid: all PKIDs
	// and posts exist, strings are of an appropriate length, etc.

	// Check if there is an existing matching association entry that will be overwritten.
	// This existing association entry will be restored if we disconnect this txn.
	prevAssociationEntry, err := bav.GetPostAssociationByAttributes(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectCreatePostAssociation: ")
	}
	// Delete the existing association entry, if exists.
	if prevAssociationEntry != nil {
		bav._deletePostAssociationEntryMappings(prevAssociationEntry)
	}

	// Construct new association entry from metadata.
	currentAssociationEntry := &PostAssociationEntry{
		AssociationID:    txHash,
		TransactorPKID:   bav.GetPKIDForPublicKey(txn.PublicKey).PKID,
		PostHash:         txMeta.PostHash,
		AppUserPKID:      bav._associationAppUserPublicKeyToPKID(txMeta.AppUserPublicKey),
		AssociationType:  txMeta.AssociationType,
		AssociationValue: txMeta.AssociationValue,
		BlockHeight:      blockHeight,
	}
	// Create the association.
	bav._setPostAssociationEntryMappings(currentAssociationEntry)

	// Add a UTXO operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeCreatePostAssociation,
		PrevPostAssociationEntry: prevAssociationEntry,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _connectDeletePostAssociation(
	txn *MsgDeSoTxn,
	txHash *BlockHash,
	blockHeight uint32,
	verifySignatures bool,
) (
	_totalInput uint64,
	_totalOutput uint64,
	_utxoOps []*UtxoOperation,
	_err error,
) {
	// Validate the starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Validate the txn TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDeletePostAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeletePostAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Connect a basic transfer to get the total input and the
	// total output without considering the txn metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures,
	)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectDeleteUserAssociation: ")
	}
	if verifySignatures {
		// _connectBasicTransfer has already checked that the txn is signed
		// by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*DeletePostAssociationMetadata)

	// Validate the txn metadata.
	if err := bav.IsValidDeletePostAssociationMetadata(txn.PublicKey, txMeta); err != nil {
		return 0, 0, nil, err
	}

	// At this point, we can assume the metadata is valid: the
	// association ID is non-null and the association entry exists.

	// Delete the association.
	prevAssociationEntry, err := bav.GetPostAssociationByID(txMeta.AssociationID)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeletePostAssociation: error fetching association %s", txMeta.AssociationID.String(),
		)
	}
	bav._deletePostAssociationEntryMappings(prevAssociationEntry)

	// Add a UTXO operation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                     OperationTypeDeletePostAssociation,
		PrevPostAssociationEntry: prevAssociationEntry,
	})
	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectCreateUserAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is a CreateUserAssociation operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreateUserAssociation: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreateUserAssociation {
		return fmt.Errorf(
			"_disconnectCreateUserAssociation: trying to revert OperationTypeCreateUserAssociation but found type %v",
			utxoOpsForTxn[operationIndex].Type,
		)
	}
	txMeta := currentTxn.TxnMeta.(*CreateUserAssociationMetadata)
	operationData := utxoOpsForTxn[operationIndex]

	// Delete the current association entry.
	currentAssociationEntry, err := bav.GetUserAssociationByAttributes(currentTxn.PublicKey, txMeta)
	if err != nil {
		return errors.Wrapf(err, "_disconnectCreateUserAssociation: ")
	}
	bav._deleteUserAssociationEntryMappings(currentAssociationEntry)

	// Set the prev association entry, if exists.
	if operationData.PrevUserAssociationEntry != nil {
		bav._setUserAssociationEntryMappings(operationData.PrevUserAssociationEntry)
	}

	// Disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) _disconnectDeleteUserAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is a DeleteUserAssociation operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectDeleteUserAssociation: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeDeleteUserAssociation {
		return fmt.Errorf(
			"_disconnectDeleteUserAssociation: trying to revert OperationTypeDeleteUserAssociation but found type %v",
			utxoOpsForTxn[operationIndex].Type,
		)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Set the prev association entry. Error if doesn't exist.
	if operationData.PrevUserAssociationEntry == nil {
		return fmt.Errorf("_disconnectDeleteUserAssociation: no deleted association entry found")
	}
	bav._setUserAssociationEntryMappings(operationData.PrevUserAssociationEntry)

	// Disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) _disconnectCreatePostAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is a CreatePostAssociation operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectCreatePostAssociation: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreatePostAssociation {
		return fmt.Errorf(
			"_disconnectCreatePostAssociation: trying to revert OperationTypeCreatePostAssociation but found type %v",
			utxoOpsForTxn[operationIndex].Type,
		)
	}
	txMeta := currentTxn.TxnMeta.(*CreatePostAssociationMetadata)
	operationData := utxoOpsForTxn[operationIndex]

	// Delete the current association entry.
	currentAssociationEntry, err := bav.GetPostAssociationByAttributes(currentTxn.PublicKey, txMeta)
	if err != nil {
		return errors.Wrapf(err, "_disconnectCreatePostAssociation: ")
	}
	bav._deletePostAssociationEntryMappings(currentAssociationEntry)

	// Set the prev association entry, if exists.
	if operationData.PrevPostAssociationEntry != nil {
		bav._setPostAssociationEntryMappings(operationData.PrevPostAssociationEntry)
	}

	// Disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

func (bav *UtxoView) _disconnectDeletePostAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// Validate the last operation is a DeletePostAssociation operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectDeletePostAssociation: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeDeletePostAssociation {
		return fmt.Errorf(
			"_disconnectDeletePostAssociation: trying to revert OperationTypeDeletePostAssociation but found type %v",
			utxoOpsForTxn[operationIndex].Type,
		)
	}
	operationData := utxoOpsForTxn[operationIndex]

	// Set the prev association entry. Error if doesn't exist.
	if operationData.PrevPostAssociationEntry == nil {
		return fmt.Errorf("_disconnectDeletePostAssociation: no deleted association entry found")
	}
	bav._setPostAssociationEntryMappings(operationData.PrevPostAssociationEntry)

	// Disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight,
	)
}

// ###########################
// ## VALIDATIONS
// ###########################

func (bav *UtxoView) IsValidCreateUserAssociationMetadata(transactorPK []byte, metadata *CreateUserAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate TransactorPKID.
	if transactorPK == nil {
		return RuleErrorAssociationInvalidTransactor // This should never happen.
	}
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorAssociationInvalidTransactor
	}

	// Validate TargetUserPKID.
	if metadata.TargetUserPublicKey == nil {
		return RuleErrorUserAssociationInvalidTargetUser
	}
	targetUserPKIDEntry := bav.GetPKIDForPublicKey(metadata.TargetUserPublicKey.ToBytes())
	if targetUserPKIDEntry == nil || targetUserPKIDEntry.isDeleted {
		return RuleErrorUserAssociationInvalidTargetUser
	}

	// Validate AppUserPKID.
	if metadata.AppUserPublicKey == nil {
		return RuleErrorAssociationInvalidAppUser
	}
	if !metadata.AppUserPublicKey.IsZeroPublicKey() {
		appUserPKIDEntry := bav.GetPKIDForPublicKey(metadata.AppUserPublicKey.ToBytes())
		if appUserPKIDEntry == nil || appUserPKIDEntry.isDeleted {
			return RuleErrorAssociationInvalidAppUser
		}
	}

	// Validate AssociationType.
	if len(metadata.AssociationType) == 0 ||
		len(metadata.AssociationType) > MaxAssociationTypeCharLength ||
		strings.HasPrefix(metadata.AssociationType, AssociationTypeReservedPrefix) {
		return RuleErrorAssociationInvalidType
	}

	// Validate AssociationValue.
	if len(metadata.AssociationValue) == 0 ||
		len(metadata.AssociationValue) > MaxAssociationValueCharLength {
		return RuleErrorAssociationInvalidValue
	}
	return nil
}

func (bav *UtxoView) IsValidDeleteUserAssociationMetadata(transactorPK []byte, metadata *DeleteUserAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate association ID is non-null.
	if metadata.AssociationID == nil {
		return RuleErrorAssociationInvalidID
	}

	// Validate association entry exists.
	associationEntry, err := bav.GetUserAssociationByID(metadata.AssociationID)
	if err != nil {
		return err
	}
	if associationEntry == nil {
		return RuleErrorAssociationNotFound
	}

	// Validate association entry was created by the same transactor.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil ||
		transactorPKIDEntry.isDeleted ||
		!transactorPKIDEntry.PKID.Eq(associationEntry.TransactorPKID) {
		return RuleErrorAssociationInvalidTransactor
	}
	return nil
}

func (bav *UtxoView) IsValidCreatePostAssociationMetadata(transactorPK []byte, metadata *CreatePostAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate TransactorPKID.
	if transactorPK == nil {
		return RuleErrorAssociationInvalidTransactor // This should never happen.
	}
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorAssociationInvalidTransactor
	}

	// Validate PostHash.
	if metadata.PostHash == nil {
		return RuleErrorPostAssociationInvalidPost
	}
	postEntry := bav.GetPostEntryForPostHash(metadata.PostHash)
	if postEntry == nil || postEntry.isDeleted {
		return RuleErrorPostAssociationInvalidPost
	}

	// Validate AppUserPKID.
	if metadata.AppUserPublicKey == nil {
		return RuleErrorAssociationInvalidAppUser
	}
	if !metadata.AppUserPublicKey.IsZeroPublicKey() {
		appUserPKIDEntry := bav.GetPKIDForPublicKey(metadata.AppUserPublicKey.ToBytes())
		if appUserPKIDEntry == nil || appUserPKIDEntry.isDeleted {
			return RuleErrorAssociationInvalidAppUser
		}
	}

	// Validate AssociationType.
	if len(metadata.AssociationType) == 0 ||
		len(metadata.AssociationType) > MaxAssociationTypeCharLength ||
		strings.HasPrefix(metadata.AssociationType, AssociationTypeReservedPrefix) {
		return RuleErrorAssociationInvalidType
	}

	// Validate AssociationValue.
	if len(metadata.AssociationValue) == 0 ||
		len(metadata.AssociationValue) > MaxAssociationValueCharLength {
		return RuleErrorAssociationInvalidValue
	}
	return nil
}

func (bav *UtxoView) IsValidDeletePostAssociationMetadata(transactorPK []byte, metadata *DeletePostAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate association ID is non-null.
	if metadata.AssociationID == nil {
		return RuleErrorAssociationInvalidID
	}

	// Validate association entry exists.
	associationEntry, err := bav.GetPostAssociationByID(metadata.AssociationID)
	if err != nil {
		return err
	}
	if associationEntry == nil {
		return RuleErrorAssociationNotFound
	}

	// Validate association entry was created by the same transactor.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil ||
		transactorPKIDEntry.isDeleted ||
		!transactorPKIDEntry.PKID.Eq(associationEntry.TransactorPKID) {
		return RuleErrorAssociationInvalidTransactor
	}
	return nil
}

// ###########################
// ## GETTERS
// ###########################

func (bav *UtxoView) GetUserAssociationByID(associationID *BlockHash) (*UserAssociationEntry, error) {
	// First, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	associationEntry, exists := bav.AssociationMapKeyToUserAssociationEntry[AssociationMapKey{AssociationID: *associationID}]
	if exists && associationEntry != nil {
		if associationEntry.isDeleted {
			// If association entry is deleted, return nil.
			return nil, nil
		}
		return associationEntry, nil
	}
	// If not found in the UTXO view, next check the database.
	return bav.GetDbAdapter().GetUserAssociationByID(associationID)
}

func (bav *UtxoView) GetPostAssociationByID(associationID *BlockHash) (*PostAssociationEntry, error) {
	// First, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	associationEntry, exists := bav.AssociationMapKeyToPostAssociationEntry[AssociationMapKey{AssociationID: *associationID}]
	if exists && associationEntry != nil {
		if associationEntry.isDeleted {
			// If association entry is deleted, return nil.
			return nil, nil
		}
		return associationEntry, nil
	}
	// If not found in the UTXO view, next check the database.
	return bav.GetDbAdapter().GetPostAssociationByID(associationID)
}

func (bav *UtxoView) GetUserAssociationByAttributes(transactorPK []byte, metadata *CreateUserAssociationMetadata) (*UserAssociationEntry, error) {
	// Convert metadata to association entry. At this point, we know the metadata
	// is already validated: PKIDs exist and string are of an acceptable length.
	associationEntry := &UserAssociationEntry{
		TransactorPKID:   bav.GetPKIDForPublicKey(transactorPK).PKID,
		TargetUserPKID:   bav.GetPKIDForPublicKey(metadata.TargetUserPublicKey.ToBytes()).PKID,
		AppUserPKID:      bav._associationAppUserPublicKeyToPKID(metadata.AppUserPublicKey),
		AssociationType:  metadata.AssociationType,
		AssociationValue: metadata.AssociationValue,
	}
	// First, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	for _, utxoAssociationEntry := range bav.AssociationMapKeyToUserAssociationEntry {
		if utxoAssociationEntry.isDeleted {
			continue
		}
		if associationEntry.Eq(utxoAssociationEntry) {
			return utxoAssociationEntry, nil
		}
	}
	// If not found in the UTXO view, next check the database.
	return bav.GetDbAdapter().GetUserAssociationByAttributes(associationEntry)
}

func (bav *UtxoView) GetPostAssociationByAttributes(transactorPK []byte, metadata *CreatePostAssociationMetadata) (*PostAssociationEntry, error) {
	// Convert metadata to association entry. At this point, we know the metadata is
	// already validated: PKIDs and posts exist and string are of an acceptable length.
	associationEntry := &PostAssociationEntry{
		TransactorPKID:   bav.GetPKIDForPublicKey(transactorPK).PKID,
		PostHash:         metadata.PostHash,
		AppUserPKID:      bav._associationAppUserPublicKeyToPKID(metadata.AppUserPublicKey),
		AssociationType:  metadata.AssociationType,
		AssociationValue: metadata.AssociationValue,
	}
	// First, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	for _, utxoAssociationEntry := range bav.AssociationMapKeyToPostAssociationEntry {
		if utxoAssociationEntry.isDeleted {
			continue
		}
		if associationEntry.Eq(utxoAssociationEntry) {
			return utxoAssociationEntry, nil
		}
	}
	// If not found in the UTXO view, next check the database.
	return bav.GetDbAdapter().GetPostAssociationByAttributes(associationEntry)
}

func (bav *UtxoView) GetUserAssociationsByAttributes(associationQuery *UserAssociationQuery) ([]*UserAssociationEntry, error) {
	// Validate query params.
	if associationQuery.TransactorPKID == nil &&
		associationQuery.TargetUserPKID == nil &&
		associationQuery.AppUserPKID == nil &&
		associationQuery.AssociationType == "" &&
		associationQuery.AssociationTypePrefix == "" &&
		associationQuery.AssociationValue == "" &&
		associationQuery.AssociationValuePrefix == "" {
		return nil, errors.New("GetUserAssociationsByAttributes: invalid query params")
	}
	if (associationQuery.AssociationType != "" && associationQuery.AssociationTypePrefix != "") ||
		(associationQuery.AssociationValue != "" && associationQuery.AssociationValuePrefix != "") {
		return nil, errors.New("GetUserAssociationsByAttributes: invalid query params")
	}
	// Store matching associations in a map indexed by AssociationID to
	// prevent duplicate associations retrieved from the db + UTXO view.
	associationEntryMap := map[*BlockHash]*UserAssociationEntry{}
	// First, check the database.
	dbAssociationEntries, err := bav.GetDbAdapter().GetUserAssociationsByAttributes(associationQuery)
	if err != nil {
		return nil, err
	}
	for _, dbAssociationEntry := range dbAssociationEntries {
		associationEntryMap[dbAssociationEntry.AssociationID] = dbAssociationEntry
	}
	// Next, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	for _, utxoAssociationEntry := range bav.AssociationMapKeyToUserAssociationEntry {
		// If TransactorPKID is set, they have to match.
		if associationQuery.TransactorPKID != nil &&
			!associationQuery.TransactorPKID.Eq(utxoAssociationEntry.TransactorPKID) {
			continue
		}
		// If TargetUserPKID is set, they have to match.
		if associationQuery.TargetUserPKID != nil &&
			!associationQuery.TargetUserPKID.Eq(utxoAssociationEntry.TargetUserPKID) {
			continue
		}
		// If AppUserPKID is set, they have to match.
		if associationQuery.AppUserPKID != nil &&
			!associationQuery.AppUserPKID.Eq(utxoAssociationEntry.AppUserPKID) {
			continue
		}
		// If AssociationType is set, they have to match.
		if associationQuery.AssociationType != "" {
			if strings.Compare(
				strings.ToLower(associationQuery.AssociationType),
				strings.ToLower(utxoAssociationEntry.AssociationType),
			) != 0 {
				continue
			}
		} else if associationQuery.AssociationTypePrefix != "" {
			// If AssociationTypePrefix is set, they have to prefix match.
			if !strings.HasPrefix(
				strings.ToLower(utxoAssociationEntry.AssociationType),
				strings.ToLower(associationQuery.AssociationTypePrefix),
			) {
				continue
			}
		}
		// If AssociationValue is set, they have to match.
		if associationQuery.AssociationValue != "" {
			if strings.Compare(associationQuery.AssociationValue, utxoAssociationEntry.AssociationValue) != 0 {
				continue
			}
		} else if associationQuery.AssociationValuePrefix != "" {
			// If AssociationValuePrefix is set, they have to prefix match.
			if !strings.HasPrefix(
				utxoAssociationEntry.AssociationValue,
				associationQuery.AssociationValuePrefix,
			) {
				continue
			}
		}
		associationEntryMap[utxoAssociationEntry.AssociationID] = utxoAssociationEntry
	}
	// Convert map to slice.
	var associationEntries []*UserAssociationEntry
	for _, matchingAssociationEntry := range associationEntryMap {
		if matchingAssociationEntry.isDeleted {
			// Don't include any deleted association entries.
			continue
		}
		associationEntries = append(associationEntries, matchingAssociationEntry)
	}
	return associationEntries, nil
}

func (bav *UtxoView) GetPostAssociationsByAttributes(associationQuery *PostAssociationQuery) ([]*PostAssociationEntry, error) {
	// Validate query params.
	if associationQuery.TransactorPKID == nil &&
		associationQuery.PostHash == nil &&
		associationQuery.AppUserPKID == nil &&
		associationQuery.AssociationType == "" &&
		associationQuery.AssociationTypePrefix == "" &&
		associationQuery.AssociationValue == "" &&
		associationQuery.AssociationValuePrefix == "" {
		return nil, errors.New("GetPostAssociationsByAttributes: invalid query params")
	}
	if (associationQuery.AssociationType != "" && associationQuery.AssociationTypePrefix != "") ||
		(associationQuery.AssociationValue != "" && associationQuery.AssociationValuePrefix != "") {
		return nil, errors.New("GetPostAssociationsByAttributes: invalid query params")
	}
	// Store matching associations in a map indexed by AssociationID to
	// prevent duplicate associations retrieved from the db + UTXO view.
	associationEntryMap := map[*BlockHash]*PostAssociationEntry{}
	// First, check the database.
	dbAssociationEntries, err := bav.GetDbAdapter().GetPostAssociationsByAttributes(associationQuery)
	if err != nil {
		return nil, err
	}
	for _, dbAssociationEntry := range dbAssociationEntries {
		associationEntryMap[dbAssociationEntry.AssociationID] = dbAssociationEntry
	}
	// Next, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	for _, utxoAssociationEntry := range bav.AssociationMapKeyToPostAssociationEntry {
		// If TransactorPKID is set, they have to match.
		if associationQuery.TransactorPKID != nil &&
			!associationQuery.TransactorPKID.Eq(utxoAssociationEntry.TransactorPKID) {
			continue
		}
		// If PostHash is set, they have to match.
		if associationQuery.PostHash != nil &&
			!associationQuery.PostHash.IsEqual(utxoAssociationEntry.PostHash) {
			continue
		}
		// If AppUserPKID is set, they have to match.
		if associationQuery.AppUserPKID != nil &&
			!associationQuery.AppUserPKID.Eq(utxoAssociationEntry.AppUserPKID) {
			continue
		}
		// If AssociationType is set, they have to match.
		if associationQuery.AssociationType != "" {
			if strings.Compare(
				strings.ToLower(associationQuery.AssociationType),
				strings.ToLower(utxoAssociationEntry.AssociationType),
			) != 0 {
				continue
			}
		} else if associationQuery.AssociationTypePrefix != "" {
			// If AssociationTypePrefix is set, they have to prefix match.
			if !strings.HasPrefix(
				strings.ToLower(utxoAssociationEntry.AssociationType),
				strings.ToLower(associationQuery.AssociationTypePrefix),
			) {
				continue
			}
		}
		// If AssociationValue is set, they have to match.
		if associationQuery.AssociationValue != "" {
			if strings.Compare(associationQuery.AssociationValue, utxoAssociationEntry.AssociationValue) != 0 {
				continue
			}
		} else if associationQuery.AssociationValuePrefix != "" {
			// If AssociationValuePrefix is set, they have to prefix match.
			if !strings.HasPrefix(
				utxoAssociationEntry.AssociationValue,
				associationQuery.AssociationValuePrefix,
			) {
				continue
			}
		}
		associationEntryMap[utxoAssociationEntry.AssociationID] = utxoAssociationEntry
	}
	// Convert map to slice.
	var associationEntries []*PostAssociationEntry
	for _, matchingAssociationEntry := range associationEntryMap {
		if matchingAssociationEntry.isDeleted {
			// Don't include any deleted association entries.
			continue
		}
		associationEntries = append(associationEntries, matchingAssociationEntry)
	}
	return associationEntries, nil
}

// ###########################
// ## SETTERS
// ###########################

func (bav *UtxoView) _setUserAssociationEntryMappings(entry *UserAssociationEntry) {
	// This function shouldn't be called with nil.
	if entry == nil {
		glog.Errorf("_setUserAssociationEntryMappings: called with nil entry; this should never happen")
		return
	}

	bav.AssociationMapKeyToUserAssociationEntry[AssociationMapKey{*entry.AssociationID}] = entry
}

func (bav *UtxoView) _deleteUserAssociationEntryMappings(entry *UserAssociationEntry) {
	// This function shouldn't be called with nil.
	if entry == nil {
		glog.Errorf("_deleteUserAssociationEntryMappings: called with nil entry; this should never happen")
		return
	}

	// Create a tombstone entry.
	tombstoneEntry := *entry
	tombstoneEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setUserAssociationEntryMappings(&tombstoneEntry)
}

func (bav *UtxoView) _setPostAssociationEntryMappings(entry *PostAssociationEntry) {
	// This function shouldn't be called with nil.
	if entry == nil {
		glog.Errorf("_setPostAssociationEntryMappings: called with nil entry; this should never happen")
		return
	}

	bav.AssociationMapKeyToPostAssociationEntry[AssociationMapKey{*entry.AssociationID}] = entry
}

func (bav *UtxoView) _deletePostAssociationEntryMappings(entry *PostAssociationEntry) {
	// This function shouldn't be called with nil.
	if entry == nil {
		glog.Errorf("_deletePostAssociationEntryMappings: called with nil entry; this should never happen")
		return
	}

	// Create a tombstone entry.
	tombstoneEntry := *entry
	tombstoneEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setPostAssociationEntryMappings(&tombstoneEntry)
}

// ###########################
// ## HELPERS
// ###########################

func (bav *UtxoView) _associationAppUserPublicKeyToPKID(publicKey *PublicKey) *PKID {
	if publicKey.IsZeroPublicKey() {
		return &ZeroPKID
	}
	return bav.GetPKIDForPublicKey(publicKey.ToBytes()).PKID
}
