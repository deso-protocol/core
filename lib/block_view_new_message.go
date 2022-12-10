package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
)

// ==================================================================
// GroupChatMessagesIndex
// ==================================================================

func (bav *UtxoView) getGroupChatMessagesIndex(groupChatMessageKey GroupChatMessageKey) (*NewMessageEntry, error) {
	mapValue, existsMapValue := bav.GroupChatMessagesIndex[groupChatMessageKey]
	if existsMapValue {
		return mapValue, nil
	}

	dbAdapter := bav.GetDbAdapter()
	dbMessageEntry, err := dbAdapter.GetGroupChatMessageEntry(groupChatMessageKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupChatMessagesIndex: ")
	}
	if dbMessageEntry != nil {
		if err := bav.setGroupChatMessagesIndex(dbMessageEntry); err != nil {
			return nil, errors.Wrapf(err, "getGroupChatMessagesIndex: ")
		}
	}
	return dbMessageEntry, nil
}

func (bav *UtxoView) setGroupChatMessagesIndex(messageEntry *NewMessageEntry) error {
	if messageEntry == nil {
		return fmt.Errorf("setGroupChatMessagesIndex: called with nil messageEntry")
	}

	if messageEntry.RecipientAccessGroupOwnerPublicKey == nil || messageEntry.RecipientAccessGroupKeyName == nil {
		return fmt.Errorf("setGroupChatMessagesIndex: called with nil recipient data")
	}

	groupChatMessageKey := MakeGroupChatMessageKey(
		*messageEntry.RecipientAccessGroupOwnerPublicKey, *messageEntry.RecipientAccessGroupKeyName, messageEntry.TimestampNanos)
	bav.GroupChatMessagesIndex[groupChatMessageKey] = messageEntry
	return nil
}

func (bav *UtxoView) deleteGroupChatMessagesIndex(messageEntry *NewMessageEntry) error {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	// As opposed to the setGroupChatMessagesIndex, we only need to do *the delete* once.
	// This is because set will delete both entries at once.
	if err := bav.setGroupChatMessagesIndex(&tombstoneMessageEntry); err != nil {
		return errors.Wrapf(err, "deleteGroupChatMessagesIndex: ")
	}
	return nil
}

// ==================================================================
// DmMessagesIndex
// ==================================================================

func (bav *UtxoView) getDmMessagesIndex(dmMessageKey DmMessageKey) (*NewMessageEntry, error) {
	mapValue, existsMapValue := bav.DmMessagesIndex[dmMessageKey]
	if existsMapValue {
		return mapValue, nil
	}

	dbAdapter := bav.GetDbAdapter()
	dbMessageEntry, err := dbAdapter.GetDmMessageEntry(dmMessageKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getDmMessagesIndex: ")
	}
	if dbMessageEntry != nil {
		if err := bav.setDmMessagesIndex(dbMessageEntry); err != nil {
			return nil, errors.Wrapf(err, "getDmMessagesIndex: ")
		}
	}
	return dbMessageEntry, nil
}

func (bav *UtxoView) setDmMessagesIndex(messageEntry *NewMessageEntry) error {
	if messageEntry == nil {
		return fmt.Errorf("setDmMessagesIndex: called with nil messageEntry")
	}

	if messageEntry.SenderAccessGroupOwnerPublicKey == nil || messageEntry.SenderAccessGroupKeyName == nil ||
		messageEntry.RecipientAccessGroupOwnerPublicKey == nil || messageEntry.RecipientAccessGroupKeyName == nil {

		return fmt.Errorf("setDmMessagesIndex: called with nil sender or recipient data")
	}

	dmMessageKey := MakeDmMessageKeyForSenderRecipient(*messageEntry.SenderAccessGroupOwnerPublicKey, *messageEntry.SenderAccessGroupKeyName,
		*messageEntry.RecipientAccessGroupOwnerPublicKey, *messageEntry.RecipientAccessGroupKeyName, messageEntry.TimestampNanos)

	bav.DmMessagesIndex[dmMessageKey] = messageEntry
	return nil
}

func (bav *UtxoView) deleteDmMessagesIndex(messageEntry *NewMessageEntry) error {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	// As opposed to the setDmMessagesIndex, we only need to do *the delete* once.
	// This is because set will delete both entries at once.
	if err := bav.setDmMessagesIndex(&tombstoneMessageEntry); err != nil {
		return errors.Wrapf(err, "deleteDmMessagesIndex: ")
	}
	return nil
}

func (bav *UtxoView) _connectNewMessage(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNewMessage {
		return 0, 0, nil, fmt.Errorf("_connectNewMessage: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NewMessageMetadata)

	if blockHeight < bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		return 0, 0, nil, RuleErrorNewMessageBeforeDeSoAccessGroups
	}

	// Check the length of the EncryptedText
	if uint64(len(txMeta.EncryptedText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageEncryptedTextLengthExceedsMax, "_connectNewMessage: "+
				"EncryptedText length (%d) exceeds max length (%d)",
			len(txMeta.EncryptedText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	// Validate sender's access group.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.SenderAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
			"SenderAccessGroupOwnerPublicKey and SenderAccessGroupKeyName are invalid")
	}

	if !bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageMessageSenderDoesNotMatchTxnPublicKey, "_connectNewMessage: "+
				"SenderAccessGroupOwnerPublicKey (%v) does not match txn.PublicKey (%v)",
			PkToString(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), bav.Params),
			PkToString(txn.PublicKey, bav.Params))
	}

	// Validate recipient's access group.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
			"RecipientAccessGroupOwnerPublicKey and RecipientAccessGroupKeyName are invalid")
	}

	if txMeta.TimestampNanos == 0 {
		return 0, 0, nil, RuleErrorNewMessageTimestampNanosCannotBeZero
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ")
	}

	messageEntry := &NewMessageEntry{
		SenderAccessGroupOwnerPublicKey:    &txMeta.SenderAccessGroupOwnerPublicKey,
		SenderAccessGroupKeyName:           &txMeta.SenderAccessGroupKeyName,
		SenderAccessGroupPublicKey:         &txMeta.SenderAccessGroupPublicKey,
		RecipientAccessGroupOwnerPublicKey: &txMeta.RecipientAccessGroupOwnerPublicKey,
		RecipientAccessGroupKeyName:        &txMeta.RecipientAccessGroupKeyName,
		RecipientAccessGroupPublicKey:      &txMeta.RecipientAccessGroupPublicKey,
		EncryptedText:                      txMeta.EncryptedText,
		TimestampNanos:                     txMeta.TimestampNanos,
		ExtraData:                          txn.ExtraData,
	}

	var prevNewMessageEntry *NewMessageEntry

	switch txMeta.NewMessageOperation {
	case NewMessageOperationCreate:
		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			dmMessageKey := MakeDmMessageKeyForSenderRecipient(txMeta.SenderAccessGroupOwnerPublicKey, txMeta.SenderAccessGroupKeyName,
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

			dmMessage, err := bav.getDmMessagesIndex(dmMessageKey)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"getting dm message from index with dm message key %v: ", dmMessageKey)
			}
			if dmMessage != nil && !dmMessage.isDeleted {
				return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageDmMessageAlreadyExists,
					"_connectNewMessage: DM thread already exists for sender (%v) and recipient (%v)",
					txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey)
			}
			err = bav.setDmMessagesIndex(messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"setting dm message in index with dm message key %v: ", dmMessageKey)
			}
		case NewMessageTypeGroupChat:
			// Fetch the group chat entry, which is indexed by the recipient's access group.
			groupChatMessageKey := MakeGroupChatMessageKey(
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)
			groupChatMessage, err := bav.getGroupChatMessagesIndex(groupChatMessageKey)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"getting group chat message from index with group chat message key %v: ", groupChatMessageKey)
			}
			if groupChatMessage != nil && !groupChatMessage.isDeleted {
				return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageGroupChatMessageAlreadyExists,
					"_connectNewMessage: Group chat thread already exists for recipient (%v)",
					txMeta.RecipientAccessGroupOwnerPublicKey)
			}
			err = bav.setGroupChatMessagesIndex(messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"setting group chat message in index with group chat message key %v: ", groupChatMessageKey)
			}
		}
	case NewMessageOperationUpdate:
		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			dmMessageKey := MakeDmMessageKeyForSenderRecipient(txMeta.SenderAccessGroupOwnerPublicKey, txMeta.SenderAccessGroupKeyName,
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

			dmMessage, err := bav.getDmMessagesIndex(dmMessageKey)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"getting dm message from index with dm message key %v: ", dmMessageKey)
			}
			if dmMessage == nil || dmMessage.isDeleted {
				return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageDmMessageDoesNotExist,
					"_connectNewMessage: DM thread does not exist for sender (%v) and recipient (%v)",
					txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey)
			}
			// Sanity-check that timestamps match.
			if dmMessage.TimestampNanos != txMeta.TimestampNanos {
				return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageDmMessageTimestampMismatch,
					"_connectNewMessage: DM thread timestamp (%v) does not match update timestamp (%v)",
					dmMessage.TimestampNanos, txMeta.TimestampNanos)
			}
			// Set the previous utxoView entry.
			copyDmMessage := *dmMessage
			prevNewMessageEntry = &copyDmMessage

			// Update the DM message entry.
			err = bav.setDmMessagesIndex(messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"setting dm message in index with dm message key %v: ", dmMessageKey)
			}
		case NewMessageTypeGroupChat:
			// Fetch the group chat entry, which is indexed by the recipient's access group.
			groupChatMessageKey := MakeGroupChatMessageKey(
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

			groupChatMessage, err := bav.getGroupChatMessagesIndex(groupChatMessageKey)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"getting group chat message from index with group chat message key %v: ", groupChatMessageKey)
			}
			if groupChatMessage == nil || groupChatMessage.isDeleted {
				return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageGroupChatMessageDoesNotExist,
					"_connectNewMessage: Group chat thread does not exist for recipient (%v)",
					txMeta.RecipientAccessGroupOwnerPublicKey)
			}
			// Sanity-check that timestamps match.
			if groupChatMessage.TimestampNanos != txMeta.TimestampNanos {
				return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageGroupMessageTimestampMismatch,
					"_connectNewMessage: Group chat thread timestamp (%v) does not match update timestamp (%v)",
					groupChatMessage.TimestampNanos, txMeta.TimestampNanos)
			}
			// Set the previous utxoView entry.
			copyGroupChatMessage := *groupChatMessage
			prevNewMessageEntry = &copyGroupChatMessage

			// Update the group chat message entry.
			err = bav.setGroupChatMessagesIndex(messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"setting group chat message in index with group chat message key %v: ", groupChatMessageKey)
			}
		}
	}

	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                OperationTypeNewMessage,
		PrevNewMessageEntry: prevNewMessageEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectNewMessage(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a PrivateMessage operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectPrivateMessage: utxoOperations are missing")
	}
	// Verify that the operation type is correct
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeNewMessage || operationType != OperationTypeNewMessage {
		return fmt.Errorf("_disconnectPrivateMessage: Trying to revert "+
			"OperationTypeNewMessage but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}
	prevUtxoOp := utxoOpsForTxn[operationIndex]

	// TODO: Add some sanity-check validation
	txMeta := currentTxn.TxnMeta.(*NewMessageMetadata)

	switch txMeta.NewMessageOperation {
	case NewMessageOperationCreate:
		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			dmMessageKey := MakeDmMessageKeyForSenderRecipient(
				txMeta.SenderAccessGroupOwnerPublicKey, txMeta.SenderAccessGroupKeyName,
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

			dmMessage, err := bav.getDmMessagesIndex(dmMessageKey)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem "+
					"getting dm message from index with dm message key %v: ", dmMessageKey)
			}
			// Sanity-check that the dm message we're reverting exists.
			if dmMessage == nil || dmMessage.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: DM thread does not exist for sender (%v) and recipient (%v)",
					txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey)
			}

			err = bav.deleteDmMessagesIndex(dmMessage)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem deleting dm message index: ")
			}
		case NewMessageTypeGroupChat:
			groupChatMessageKey := MakeGroupChatMessageKey(
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)
			groupChatMessage, err := bav.getGroupChatMessagesIndex(groupChatMessageKey)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem "+
					"getting group chat message from index with group chat message key %v: ", groupChatMessageKey)
			}
			// Sanity-check that the group chat message we're reverting exists.
			if groupChatMessage == nil || groupChatMessage.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: Group chat thread does not exist for group chat key (%v)",
					groupChatMessageKey)
			}

			err = bav.deleteGroupChatMessagesIndex(groupChatMessage)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem deleting group chat message index: ")
			}
		}
	case NewMessageOperationUpdate:
		// Make sure the utxoOp previous message is not empty.
		if prevUtxoOp.PrevNewMessageEntry == nil {
			return fmt.Errorf("_disconnectNewMessage: Previous DM message entry is nil")
		}

		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			dmMessageKey := MakeDmMessageKeyForSenderRecipient(
				txMeta.SenderAccessGroupOwnerPublicKey, txMeta.SenderAccessGroupKeyName,
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)
			dmMessage, err := bav.getDmMessagesIndex(dmMessageKey)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem "+
					"getting dm message from index with dm message key %v: ", dmMessageKey)
			}

			// Sanity-check that the dm message we're reverting exists.
			if dmMessage == nil || dmMessage.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: DM thread does not exist for dm message key (%v)",
					dmMessageKey)
			}

			// Revert the dm message entry.
			err = bav.setDmMessagesIndex(prevUtxoOp.PrevNewMessageEntry)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem "+
					"setting dm message in index with dm message key %v: ", dmMessageKey)
			}
		case NewMessageTypeGroupChat:
			groupChatMessageKey := MakeGroupChatMessageKey(
				txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)
			groupChatMessage, err := bav.getGroupChatMessagesIndex(groupChatMessageKey)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem "+
					"getting group chat message from index with group chat message key %v: ", groupChatMessageKey)
			}

			// Sanity-check that the group chat message we're reverting exists.
			if groupChatMessage == nil || groupChatMessage.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: Group chat thread does not exist for group chat key (%v)",
					groupChatMessageKey)
			}

			// Revert the group chat message entry.
			err = bav.setGroupChatMessagesIndex(prevUtxoOp.PrevNewMessageEntry)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem "+
					"setting group chat message in index with group chat message key %v: ", groupChatMessageKey)
			}
		}
	}

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
