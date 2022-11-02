package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/golang/glog"
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
	// Error if before starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreateUserAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectCreateUserAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CreateUserAssociationMetadata)

	// Validate the txn metadata.
	err := bav.IsValidCreateUserAssociationMetadata(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, err
	}

	// Construct association entry from metadata. At this point, we can assume the metadata
	// is valid: all PKIDs exist, strings lengths are within the correct range, etc.
	association := &UserAssociationEntry{
		AssociationID:    txHash,
		TransactorPKID:   bav.GetPKIDForPublicKey(txn.PublicKey).PKID,
		TargetUserPKID:   bav.GetPKIDForPublicKey(txMeta.TargetUserPublicKey.ToBytes()).PKID,
		AssociationType:  txMeta.AssociationType,
		AssociationValue: txMeta.AssociationValue,
		BlockHeight:      blockHeight,
	}
	_ = association

	// TODO
	return 0, 0, nil, nil
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
	// Error if before starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDeleteUserAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeleteUserAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*DeleteUserAssociationMetadata)
	_ = txMeta

	// Validate the txn metadata.
	err := bav.IsValidDeleteUserAssociationMetadata(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, err
	}

	// Delete the association.
	associationEntry, err := bav.GetUserAssociationByID(txMeta.AssociationID)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeleteUserAssociation: error fetching association %s", txMeta.AssociationID.String(),
		)
	}
	bav._deleteUserAssociationEntryMappings(associationEntry)

	// TODO
	return 0, 0, nil, nil
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
	// Error if before starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeCreatePostAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectCreatePostAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*CreatePostAssociationMetadata)

	// Validate the txn metadata.
	err := bav.IsValidCreatePostAssociationMetadata(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, err
	}

	// Construct association entry from metadata. At this point, we can assume the metadata
	// is valid: all PKIDs and posts exist, strings lengths are within the correct range, etc.
	postHashBytes, _ := hex.DecodeString(txMeta.PostHashHex)
	association := &PostAssociationEntry{
		AssociationID:    txHash,
		TransactorPKID:   bav.GetPKIDForPublicKey(txn.PublicKey).PKID,
		PostHash:         NewBlockHash(postHashBytes),
		AssociationType:  txMeta.AssociationType,
		AssociationValue: txMeta.AssociationValue,
		BlockHeight:      blockHeight,
	}
	_ = association

	// TODO
	return 0, 0, nil, nil
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
	// Error if before starting block height.
	if blockHeight < bav.Params.ForkHeights.AssociationsBlockHeight {
		return 0, 0, nil, RuleErrorAssociationBeforeBlockHeight
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeDeletePostAssociation {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeletePostAssociation: called with bad TxnType %s", txn.TxnMeta.GetTxnType().String(),
		)
	}

	// Grab the txn metadata.
	txMeta := txn.TxnMeta.(*DeletePostAssociationMetadata)
	_ = txMeta

	// Validate the txn metadata.
	err := bav.IsValidDeletePostAssociationMetadata(txn.PublicKey, txMeta)
	if err != nil {
		return 0, 0, nil, err
	}

	// Delete the association.
	associationEntry, err := bav.GetPostAssociationByID(txMeta.AssociationID)
	if err != nil {
		return 0, 0, nil, fmt.Errorf(
			"_connectDeletePostAssociation: error fetching association %s", txMeta.AssociationID.String(),
		)
	}
	bav._deletePostAssociationEntryMappings(associationEntry)

	// TODO
	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectCreateUserAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// TODO
	return nil
}

func (bav *UtxoView) _disconnectDeleteUserAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// TODO
	return nil
}

func (bav *UtxoView) _disconnectCreatePostAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// TODO
	return nil
}

func (bav *UtxoView) _disconnectDeletePostAssociation(
	operationType OperationType,
	currentTxn *MsgDeSoTxn,
	txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation,
	blockHeight uint32,
) error {
	// TODO
	return nil
}

// ###########################
// ## VALIDATIONS
// ###########################

func (bav *UtxoView) IsValidCreateUserAssociationMetadata(transactorPK []byte, metadata *CreateUserAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate TransactorPKID.
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorAssociationInvalidTransactor
	}

	// Validate TargetUserPKID.
	targetUserPKIDEntry := bav.GetPKIDForPublicKey(metadata.TargetUserPublicKey.ToBytes())
	if targetUserPKIDEntry == nil || targetUserPKIDEntry.isDeleted {
		return RuleErrorUserAssociationInvalidTargetUser
	}

	// Validate AssociationType.
	if len(metadata.AssociationType) == 0 ||
		len(metadata.AssociationType) > MaxAssociationTypeCharLength ||
		strings.HasPrefix(metadata.AssociationType, AssociationTypeReservedPrefix) {
		return RuleErrorAssociationInvalidType
	}

	// Validate AssociationValue.
	if len(metadata.AssociationType) == 0 ||
		len(metadata.AssociationType) > MaxAssociationValueCharLength {
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
	transactorPKIDEntry := bav.GetPKIDForPublicKey(transactorPK)
	if transactorPKIDEntry == nil || transactorPKIDEntry.isDeleted {
		return RuleErrorAssociationInvalidTransactor
	}

	// Validate PostHashHex.
	postHashBytes, err := hex.DecodeString(metadata.PostHashHex)
	if err != nil {
		return RuleErrorPostAssociationInvalidPost
	}
	postEntry := bav.GetPostEntryForPostHash(NewBlockHash(postHashBytes))
	if postEntry == nil || postEntry.isDeleted {
		return RuleErrorPostAssociationInvalidPost
	}

	// Validate AssociationType.
	if len(metadata.AssociationType) == 0 ||
		len(metadata.AssociationType) > MaxAssociationTypeCharLength ||
		strings.HasPrefix(metadata.AssociationType, AssociationTypeReservedPrefix) {
		return RuleErrorAssociationInvalidType
	}

	// Validate AssociationValue.
	if len(metadata.AssociationType) == 0 ||
		len(metadata.AssociationType) > MaxAssociationValueCharLength {
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
	// First, check UTXO view.
	associationEntry, exists := bav.AssociationMapKeyToUserAssociationEntry[AssociationMapKey{AssociationID: *associationID}]
	if exists {
		return associationEntry, nil
	}
	// Next, check database.
	return bav.GetDbAdapter().GetUserAssociationByID(associationID)
}

func (bav *UtxoView) GetPostAssociationByID(associationID *BlockHash) (*PostAssociationEntry, error) {
	// First, check UTXO view.
	associationEntry, exists := bav.AssociationMapKeyToPostAssociationEntry[AssociationMapKey{AssociationID: *associationID}]
	if exists {
		return associationEntry, nil
	}
	// Next, check database.
	return bav.GetDbAdapter().GetPostAssociationByID(associationID)
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
