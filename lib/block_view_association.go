package lib

import (
	"bytes"
	"fmt"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

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
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
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
	//
	// Additionally, note that, because we index associations by the transactorPKID,
	// it is impossible for someone to create an association on someone else's behalf.
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	if prevAssociationEntry != nil {
		bav._deleteUserAssociationEntryMappings(prevAssociationEntry)
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	var prevExtraData map[string][]byte
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	if prevAssociationEntry != nil {
		prevExtraData = prevAssociationEntry.ExtraData
	}

	// Construct new association entry from metadata.
	currentAssociationEntry := &UserAssociationEntry{
		AssociationID:    txHash,
		TransactorPKID:   bav.GetPKIDForPublicKey(txn.PublicKey).PKID,
		TargetUserPKID:   bav.GetPKIDForPublicKey(txMeta.TargetUserPublicKey.ToBytes()).PKID,
		AppPKID:          bav._associationAppPublicKeyToPKID(txMeta.AppPublicKey),
		AssociationType:  txMeta.AssociationType,
		AssociationValue: txMeta.AssociationValue,
		ExtraData:        mergeExtraData(prevExtraData, txn.ExtraData),
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
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	prevAssociationEntry, err := bav.GetUserAssociationByID(txMeta.AssociationID)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeleteUserAssociation: error fetching association %s", txMeta.AssociationID.String(),
		)
	}
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	if prevAssociationEntry == nil {
		// This should never happen as we validate the association
		// exists when we validate the txn metadata.
		return 0, 0, nil, errors.New("_connectDeleteUserAssociation: no existing association entry found")
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
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
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
	//
	// Additionally, note that, because we index associations by the transactorPKID,
	// it is impossible for someone to create an association on someone else's behalf.
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	if prevAssociationEntry != nil {
		bav._deletePostAssociationEntryMappings(prevAssociationEntry)
	}

	// Retrieve existing ExtraData to merge with any new ExtraData.
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	var prevExtraData map[string][]byte
	if prevAssociationEntry != nil {
		prevExtraData = prevAssociationEntry.ExtraData
	}

	// Construct new association entry from metadata.
	currentAssociationEntry := &PostAssociationEntry{
		AssociationID:    txHash,
		TransactorPKID:   bav.GetPKIDForPublicKey(txn.PublicKey).PKID,
		PostHash:         txMeta.PostHash,
		AppPKID:          bav._associationAppPublicKeyToPKID(txMeta.AppPublicKey),
		AssociationType:  txMeta.AssociationType,
		AssociationValue: txMeta.AssociationValue,
		ExtraData:        mergeExtraData(prevExtraData, txn.ExtraData),
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
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
	if prevAssociationEntry == nil {
		// This should never happen as we validate the association
		// exists when we validate the txn metadata.
		return 0, 0, nil, errors.New("_connectDeletePostAssociation: no existing association entry found")
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
	if currentAssociationEntry == nil {
		return errors.New("_disconnectCreateUserAssociation: no created association entry found")
	}
	bav._deleteUserAssociationEntryMappings(currentAssociationEntry)

	// Set the prev association entry, if exists.
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
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
	if currentAssociationEntry == nil {
		return errors.New("_disconnectCreatePostAssociation: no created association entry found")
	}
	bav._deletePostAssociationEntryMappings(currentAssociationEntry)

	// Set the prev association entry, if exists.
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
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
	// Note that we don't need to check isDeleted because the Get returns nil if isDeleted=true
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

func isValidAssociationType(associationType []byte) error {
	if len(associationType) == 0 ||
		len(associationType) > MaxAssociationTypeByteLength ||
		bytes.HasPrefix(associationType, []byte(AssociationTypeReservedPrefix)) ||
		bytes.IndexByte(associationType, AssociationNullTerminator) != -1 {
		return RuleErrorAssociationInvalidType
	}
	return nil
}

func isValidAssociationValue(associationValue []byte) error {
	if len(associationValue) == 0 ||
		len(associationValue) > MaxAssociationValueByteLength ||
		bytes.IndexByte(associationValue, AssociationNullTerminator) != -1 {
		return RuleErrorAssociationInvalidValue
	}
	return nil
}

func (bav *UtxoView) isValidAppPublicKey(appPublicKey *PublicKey) error {
	// Validate AppPKID.
	if appPublicKey == nil {
		return RuleErrorAssociationInvalidApp
	}
	if !appPublicKey.IsZeroPublicKey() {
		return bav.existsAssociationPublicKeyBytes(appPublicKey.ToBytes())
	}
	return nil
}

func (bav *UtxoView) existsAssociationPublicKeyBytes(publicKey []byte) error {
	if publicKey == nil {
		return errors.New("public key provided is nil")
	}
	pkidEntry := bav.GetPKIDForPublicKey(publicKey)
	if pkidEntry == nil || pkidEntry.isDeleted {
		return errors.New("pkid entry not found")
	}
	return nil
}

func (bav *UtxoView) IsValidCreateUserAssociationMetadata(transactorPK []byte, metadata *CreateUserAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate TransactorPKID.
	if err := bav.existsAssociationPublicKeyBytes(transactorPK); err != nil {
		return RuleErrorAssociationInvalidTransactor
	}

	// Validate TargetUserPKID.
	if metadata.TargetUserPublicKey == nil {
		return RuleErrorUserAssociationInvalidTargetUser
	}
	if err := bav.existsAssociationPublicKeyBytes(metadata.TargetUserPublicKey.ToBytes()); err != nil {
		return RuleErrorUserAssociationInvalidTargetUser
	}

	// Validate AppPKID.
	if err := bav.isValidAppPublicKey(metadata.AppPublicKey); err != nil {
		return RuleErrorAssociationInvalidApp
	}

	// Validate AssociationType.
	if err := isValidAssociationType(metadata.AssociationType); err != nil {
		return RuleErrorAssociationInvalidType
	}

	// Validate AssociationValue.
	if err := isValidAssociationValue(metadata.AssociationValue); err != nil {
		return RuleErrorAssociationInvalidValue
	}
	return nil
}

func (bav *UtxoView) IsValidDeleteUserAssociationMetadata(transactorPK []byte, metadata *DeleteUserAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate transactor public key is non-null.
	if transactorPK == nil {
		return RuleErrorAssociationInvalidTransactor
	}

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
	if err := bav.existsAssociationPublicKeyBytes(transactorPK); err != nil {
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

	// Validate AppPKID.
	if err := bav.isValidAppPublicKey(metadata.AppPublicKey); err != nil {
		return RuleErrorAssociationInvalidApp
	}

	// Validate AssociationType.
	if err := isValidAssociationType(metadata.AssociationType); err != nil {
		return RuleErrorAssociationInvalidType
	}

	// Validate AssociationValue.
	if err := isValidAssociationValue(metadata.AssociationValue); err != nil {
		return RuleErrorAssociationInvalidValue
	}
	return nil
}

func (bav *UtxoView) IsValidDeletePostAssociationMetadata(transactorPK []byte, metadata *DeletePostAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate transactor public key is non-null.
	if transactorPK == nil {
		return RuleErrorAssociationInvalidTransactor
	}

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

func (bav *UtxoView) _isValidUserAssociationQuery(associationQuery *UserAssociationQuery) error {
	if associationQuery.TransactorPKID == nil &&
		associationQuery.TargetUserPKID == nil &&
		associationQuery.AppPKID == nil &&
		len(associationQuery.AssociationType) == 0 &&
		len(associationQuery.AssociationTypePrefix) == 0 &&
		len(associationQuery.AssociationValue) == 0 &&
		len(associationQuery.AssociationValuePrefix) == 0 {
		return errors.New("invalid query params: none provided")
	}
	if len(associationQuery.AssociationType) > 0 && len(associationQuery.AssociationTypePrefix) > 0 {
		return errors.New("invalid query params: both AssociationType and AssociationTypePrefix provided")
	}
	if len(associationQuery.AssociationValue) > 0 && len(associationQuery.AssociationValuePrefix) > 0 {
		return errors.New("invalid query params: both AssociationValue and AssociationValuePrefix provided")
	}
	if associationQuery.Limit < 0 {
		return errors.New("invalid query params: negative Limit provided")
	}
	if associationQuery.LastSeenAssociationID != nil {
		lastSeenAssociationEntry, err := bav.GetUserAssociationByID(associationQuery.LastSeenAssociationID)
		if err != nil {
			return err
		}
		if lastSeenAssociationEntry == nil {
			return errors.New("invalid query params: LastSeenAssociationEntry not found")
		}
	}
	return nil
}

func (bav *UtxoView) _isValidCountUserAssociationQuery(associationQuery *UserAssociationQuery) error {
	if err := bav._isValidUserAssociationQuery(associationQuery); err != nil {
		return err
	}
	if associationQuery.Limit > 0 {
		return errors.New("invalid query params: cannot provide Limit")
	}
	if associationQuery.LastSeenAssociationID != nil {
		return errors.New("invalid query params: cannot provide LastSeenAssociationID")
	}
	if associationQuery.SortDescending {
		return errors.New("invalid query params: cannot provide SortDescending")
	}
	return nil
}

func (bav *UtxoView) _isValidPostAssociationQuery(associationQuery *PostAssociationQuery) error {
	if associationQuery.TransactorPKID == nil &&
		associationQuery.PostHash == nil &&
		associationQuery.AppPKID == nil &&
		len(associationQuery.AssociationType) == 0 &&
		len(associationQuery.AssociationTypePrefix) == 0 &&
		len(associationQuery.AssociationValue) == 0 &&
		len(associationQuery.AssociationValuePrefix) == 0 {
		return errors.New("invalid query params: none provided")
	}
	if len(associationQuery.AssociationType) > 0 && len(associationQuery.AssociationTypePrefix) > 0 {
		return errors.New("invalid query params: both AssociationType and AssociationTypePrefix provided")
	}
	if len(associationQuery.AssociationValue) > 0 && len(associationQuery.AssociationValuePrefix) > 0 {
		return errors.New("invalid query params: both AssociationValue and AssociationValuePrefix provided")
	}
	if associationQuery.Limit < 0 {
		return errors.New("invalid query params: negative Limit provided")
	}
	if associationQuery.LastSeenAssociationID != nil {
		lastSeenAssociationEntry, err := bav.GetPostAssociationByID(associationQuery.LastSeenAssociationID)
		if err != nil {
			return err
		}
		if lastSeenAssociationEntry == nil {
			return errors.New("invalid query params: LastSeenAssociationEntry not found")
		}
	}
	return nil
}

func (bav *UtxoView) _isValidCountPostAssociationQuery(associationQuery *PostAssociationQuery) error {
	if err := bav._isValidPostAssociationQuery(associationQuery); err != nil {
		return err
	}
	if associationQuery.Limit > 0 {
		return errors.New("invalid query params: cannot provide Limit")
	}
	if associationQuery.LastSeenAssociationID != nil {
		return errors.New("invalid query params: cannot provide LastSeenAssociationID")
	}
	if associationQuery.SortDescending {
		return errors.New("invalid query params: cannot provide SortDescending")
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
		AppPKID:          bav._associationAppPublicKeyToPKID(metadata.AppPublicKey),
		AssociationType:  metadata.AssociationType,
		AssociationValue: metadata.AssociationValue,
	}
	// First, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	isDeleted := false
	for _, utxoViewAssociationEntry := range bav.AssociationMapKeyToUserAssociationEntry {
		if !associationEntry.Eq(utxoViewAssociationEntry) {
			continue
		}
		if utxoViewAssociationEntry.isDeleted {
			// If there is a deleted matching association entry in the UTXO view, we need
			// to keep searching the UTXO view since there could be other non-deleted
			// matches. There can be an arbitrary number of deleted matching association
			// entries, but there will only ever be zero or one non-deleted matching
			// association entry, since "updating" a matching association entry deletes
			// the old one and creates a new one with a new association ID. If we don't
			// find any matches in the UTXO view, we return nil below, before checking
			// the db which would return a deleted association entry.
			isDeleted = true
			continue
		}
		return utxoViewAssociationEntry, nil
	}
	if isDeleted {
		return nil, nil
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
		AppPKID:          bav._associationAppPublicKeyToPKID(metadata.AppPublicKey),
		AssociationType:  metadata.AssociationType,
		AssociationValue: metadata.AssociationValue,
	}
	// First, check the UTXO view for most recent association entries which
	// take priority over any with the same AssociationID from the database.
	isDeleted := false
	for _, utxoViewAssociationEntry := range bav.AssociationMapKeyToPostAssociationEntry {
		if !associationEntry.Eq(utxoViewAssociationEntry) {
			continue
		}
		if utxoViewAssociationEntry.isDeleted {
			// If there is a deleted matching association entry in the UTXO view, we need
			// to keep searching the UTXO view since there could be other non-deleted
			// matches. There can be an arbitrary number of deleted matching association
			// entries, but there will only ever be zero or one non-deleted matching
			// association entry, since "updating" a matching association entry deletes
			// the old one and creates a new one with a new association ID. If we don't
			// find any matches in the UTXO view, we return nil below, before checking
			// the db which would return a deleted association entry.
			isDeleted = true
			continue
		}
		return utxoViewAssociationEntry, nil
	}
	if isDeleted {
		return nil, nil
	}
	// If not found in the UTXO view, next check the database.
	return bav.GetDbAdapter().GetPostAssociationByAttributes(associationEntry)
}

func (bav *UtxoView) GetUserAssociationsByAttributes(associationQuery *UserAssociationQuery) ([]*UserAssociationEntry, error) {
	// Validate query params.
	if err := bav._isValidUserAssociationQuery(associationQuery); err != nil {
		return nil, errors.Wrap(err, "GetUserAssociationsByAttributes: ")
	}
	// First, pull matching association entries from the UTXO view so that
	// we can track all association IDs from the view and can properly limit the
	// number of entries retrieved from the database.
	newAssociationEntries, allUtxoViewAssociationIds := bav._getUtxoViewUserAssociationEntriesByAttributes(associationQuery)
	// Check the database for matching association entries, excluding all association ids from the view
	dbAssociationEntries, prefixType, err := bav.GetDbAdapter().GetUserAssociationsByAttributes(associationQuery, allUtxoViewAssociationIds)
	if err != nil {
		return nil, errors.Wrapf(err, "GetUserAssociationsByAttributes: ")
	}
	// Sort the UTXO view association and DB entries according to the query's specified sort order.
	sortedAssociationEntries, err := bav.GetDbAdapter().SortUserAssociationEntriesByPrefix(
		append(newAssociationEntries, dbAssociationEntries...), prefixType, associationQuery.SortDescending,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "GetUserAssociationsByAttributes: ")
	}
	startIndex := 0
	if associationQuery.LastSeenAssociationID != nil {
		for ii, associationEntry := range sortedAssociationEntries {
			if associationEntry.AssociationID.IsEqual(associationQuery.LastSeenAssociationID) {
				startIndex = ii + 1
				break
			}
		}
	}

	maxIndex := startIndex + associationQuery.Limit
	if maxIndex == 0 || maxIndex > len(sortedAssociationEntries) {
		maxIndex = len(sortedAssociationEntries)
	}
	return sortedAssociationEntries[startIndex:maxIndex], nil
}

func (bav *UtxoView) CountUserAssociationsByAttributes(associationQuery *UserAssociationQuery) (uint64, error) {
	// Validate query params.
	if err := bav._isValidCountUserAssociationQuery(associationQuery); err != nil {
		return 0, errors.Wrap(err, "CountUserAssociationsByAttributes: ")
	}
	// First pull matching association entries from the UTXO view so that
	// we can track all association IDs from the view and can properly limit
	// the number of entries retrieved from the database.
	newUtxoViewAssociationEntries, allUtxoViewAssociationIds := bav._getUtxoViewUserAssociationEntriesByAttributes(associationQuery)
	// Pull matching association IDs from the db.
	dbAssociationIds, _, err := bav.GetDbAdapter().GetUserAssociationIdsByAttributes(associationQuery, allUtxoViewAssociationIds)
	if err != nil {
		return 0, errors.Wrapf(err, "CountUserAssociationsByAttributes: ")
	}
	return uint64(len(newUtxoViewAssociationEntries) + dbAssociationIds.Size()), nil
}

func (bav *UtxoView) _getUtxoViewUserAssociationEntriesByAttributes(
	associationQuery *UserAssociationQuery,
) ([]*UserAssociationEntry, *Set[BlockHash]) {
	// Returns a slice of new association entries in the UTXO view as well as a map of deleted entry IDs.
	var newAssociationEntries []*UserAssociationEntry
	allAssociationIds := NewSet([]BlockHash{})
	for _, associationEntry := range bav.AssociationMapKeyToUserAssociationEntry {
		if !_isMatchingUtxoUserAssociationEntry(associationQuery, associationEntry) {
			continue
		}
		allAssociationIds.Add(*associationEntry.AssociationID)
		if !associationEntry.isDeleted {
			newAssociationEntries = append(newAssociationEntries, associationEntry)
		}
	}
	return newAssociationEntries, allAssociationIds
}

func _isMatchingUtxoUserAssociationEntry(associationQuery *UserAssociationQuery, associationEntry *UserAssociationEntry) bool {
	// If TransactorPKID is set, they have to match.
	if associationQuery.TransactorPKID != nil &&
		!associationQuery.TransactorPKID.Eq(associationEntry.TransactorPKID) {
		return false
	}
	// If TargetUserPKID is set, they have to match.
	if associationQuery.TargetUserPKID != nil &&
		!associationQuery.TargetUserPKID.Eq(associationEntry.TargetUserPKID) {
		return false
	}
	// If AppPKID is set, they have to match.
	if associationQuery.AppPKID != nil &&
		!associationQuery.AppPKID.Eq(associationEntry.AppPKID) {
		return false
	}
	// If AssociationType is set, they have to match.
	if len(associationQuery.AssociationType) > 0 {
		if !_isMatchingAssociationType(associationQuery.AssociationType, associationEntry.AssociationType) {
			return false
		}
	} else if len(associationQuery.AssociationTypePrefix) > 0 {
		// If AssociationTypePrefix is set, they have to prefix match.
		if !_isMatchingAssociationTypePrefix(associationEntry.AssociationType, associationQuery.AssociationTypePrefix) {
			return false
		}
	}
	// If AssociationValue is set, they have to match.
	if len(associationQuery.AssociationValue) > 0 {
		if !bytes.Equal(associationQuery.AssociationValue, associationEntry.AssociationValue) {
			return false
		}
	} else if len(associationQuery.AssociationValuePrefix) > 0 {
		// If AssociationValuePrefix is set, they have to prefix match.
		if !bytes.HasPrefix(associationEntry.AssociationValue, associationQuery.AssociationValuePrefix) {
			return false
		}
	}
	return true
}

func (bav *UtxoView) GetPostAssociationsByAttributes(associationQuery *PostAssociationQuery) ([]*PostAssociationEntry, error) {
	// Validate query params.
	if err := bav._isValidPostAssociationQuery(associationQuery); err != nil {
		return nil, errors.Wrap(err, "GetPostAssociationsByAttributes: ")
	}
	// First, pull matching association entries from the UTXO view so that
	// we can track all association IDs from the view and can properly limit the
	// number of entries retrieved from the database.
	newUtxoViewAssociationEntries, utxoViewAssociationIds := bav._getUtxoViewPostAssociationEntriesByAttributes(associationQuery)
	// Check the database for matching association entries.
	dbAssociationEntries, prefixType, err := bav.GetDbAdapter().GetPostAssociationsByAttributes(associationQuery, utxoViewAssociationIds)
	if err != nil {
		return nil, errors.Wrapf(err, "GetPostAssociationsByAttributes: ")
	}
	// Sort the UTXO view association entries and DB entries according to the query's specified sort order.
	sortedAssociationEntries, err := bav.GetDbAdapter().SortPostAssociationEntriesByPrefix(
		append(newUtxoViewAssociationEntries, dbAssociationEntries...), prefixType, associationQuery.SortDescending,
	)
	if err != nil {
		return nil, errors.Wrapf(err, "GetPostAssociationsByAttributes: ")
	}
	startIndex := 0
	if associationQuery.LastSeenAssociationID != nil {
		for ii, associationEntry := range sortedAssociationEntries {
			if associationEntry.AssociationID.IsEqual(associationQuery.LastSeenAssociationID) {
				startIndex = ii + 1
				break
			}
		}
	}

	maxIndex := startIndex + associationQuery.Limit
	if maxIndex == 0 || maxIndex > len(sortedAssociationEntries) {
		maxIndex = len(sortedAssociationEntries)
	}
	return sortedAssociationEntries[startIndex:maxIndex], nil
}

func (bav *UtxoView) CountPostAssociationsByAttributes(associationQuery *PostAssociationQuery) (uint64, error) {
	// Validate query params.
	if err := bav._isValidCountPostAssociationQuery(associationQuery); err != nil {
		return 0, errors.Wrapf(err, "CountPostAssociationsByAttributes: ")
	}
	// First pull matching association entries from the UTXO view so that
	// we can track all association IDs from the view and can properly limit
	// the number of entries retrieved from the database.
	newUtxoViewAssociationEntries, allUtxoViewAssociationIds := bav._getUtxoViewPostAssociationEntriesByAttributes(associationQuery)
	// Pull matching association IDs from the db.
	dbAssociationIds, _, err := bav.GetDbAdapter().GetPostAssociationIdsByAttributes(associationQuery, allUtxoViewAssociationIds)
	if err != nil {
		return 0, errors.Wrapf(err, "CountPostAssociationsByAttributes: ")
	}
	return uint64(len(newUtxoViewAssociationEntries) + dbAssociationIds.Size()), nil
}

func (bav *UtxoView) _getUtxoViewPostAssociationEntriesByAttributes(
	associationQuery *PostAssociationQuery,
) ([]*PostAssociationEntry, *Set[BlockHash]) {
	// Returns a slice of new association entries in the UTXO view as well as a map of deleted entry IDs.
	var newAssociationEntries []*PostAssociationEntry
	allAssociationIds := NewSet([]BlockHash{})
	for _, associationEntry := range bav.AssociationMapKeyToPostAssociationEntry {
		if !_isMatchingUtxoPostAssociationEntry(associationQuery, associationEntry) {
			continue
		}
		allAssociationIds.Add(*associationEntry.AssociationID)
		if !associationEntry.isDeleted {
			newAssociationEntries = append(newAssociationEntries, associationEntry)
		}
	}
	return newAssociationEntries, allAssociationIds
}

func _isMatchingUtxoPostAssociationEntry(associationQuery *PostAssociationQuery, associationEntry *PostAssociationEntry) bool {
	// If TransactorPKID is set, they have to match.
	if associationQuery.TransactorPKID != nil &&
		!associationQuery.TransactorPKID.Eq(associationEntry.TransactorPKID) {
		return false
	}
	// If PostHash is set, they have to match.
	if associationQuery.PostHash != nil &&
		!associationQuery.PostHash.IsEqual(associationEntry.PostHash) {
		return false
	}
	// If AppPKID is set, they have to match.
	if associationQuery.AppPKID != nil &&
		!associationQuery.AppPKID.Eq(associationEntry.AppPKID) {
		return false
	}
	// If AssociationType is set, they have to match.
	if len(associationQuery.AssociationType) > 0 {
		if !_isMatchingAssociationType(associationQuery.AssociationType, associationEntry.AssociationType) {
			return false
		}
	} else if len(associationQuery.AssociationTypePrefix) > 0 {
		// If AssociationTypePrefix is set, they have to prefix match.
		if !_isMatchingAssociationTypePrefix(associationEntry.AssociationType, associationQuery.AssociationTypePrefix) {
			return false
		}
	}
	// If AssociationValue is set, they have to match.
	if len(associationQuery.AssociationValue) > 0 {
		if !bytes.Equal(associationQuery.AssociationValue, associationEntry.AssociationValue) {
			return false
		}
	} else if len(associationQuery.AssociationValuePrefix) > 0 {
		// If AssociationValuePrefix is set, they have to prefix match.
		if !bytes.HasPrefix(associationEntry.AssociationValue, associationQuery.AssociationValuePrefix) {
			return false
		}
	}
	return true
}

func _isMatchingAssociationType(associationType1 []byte, associationType2 []byte) bool {
	return bytes.Equal(bytes.ToLower(associationType1), bytes.ToLower(associationType2))
}

func _isMatchingAssociationTypePrefix(associationType []byte, associationTypePrefix []byte) bool {
	return bytes.HasPrefix(bytes.ToLower(associationType), bytes.ToLower(associationTypePrefix))
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

	bav.AssociationMapKeyToUserAssociationEntry[entry.ToMapKey()] = entry
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

	bav.AssociationMapKeyToPostAssociationEntry[entry.ToMapKey()] = entry
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

func (bav *UtxoView) _associationAppPublicKeyToPKID(publicKey *PublicKey) *PKID {
	if publicKey.IsZeroPublicKey() {
		return &ZeroPKID
	}
	return bav.GetPKIDForPublicKey(publicKey.ToBytes()).PKID
}
