package lib

import "fmt"

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

	// TODO
	return 0, 0, 0, nil
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
	return nil // TODO
}

func (bav *UtxoView) IsValidDeleteUserAssociationMetadata(transactorPK []byte, metadata *DeleteUserAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate association ID is non-null.
	if metadata.AssociationID == nil {
		return RuleErrorInvalidAssociationID
	}

	// Validate association entry exists.
	associationEntry, err := bav.GetUserAssociationByID(metadata.AssociationID)
	if err != nil {
		return err
	}
	if associationEntry == nil {
		return RuleErrorAssociationNotFound
	}

	// Validate association entry belongs to the transactor.
	// TODO
	return nil
}

func (bav *UtxoView) IsValidCreatePostAssociationMetadata(transactorPK []byte, metadata *CreatePostAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.
	return nil // TODO
}

func (bav *UtxoView) IsValidDeletePostAssociationMetadata(transactorPK []byte, metadata *DeletePostAssociationMetadata) error {
	// Returns an error if the input metadata is invalid. Otherwise, returns nil.

	// Validate association ID is non-null.
	if metadata.AssociationID == nil {
		return RuleErrorInvalidAssociationID
	}

	// Validate association entry exists.
	associationEntry, err := bav.GetPostAssociationByID(metadata.AssociationID)
	if err != nil {
		return err
	}
	if associationEntry == nil {
		return RuleErrorAssociationNotFound
	}

	// Validate association entry belongs to the transactor.
	// TODO
	return nil
}

// ###########################
// ## GETTERS / SETTERS
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
