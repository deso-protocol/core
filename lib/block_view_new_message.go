package lib

import (
	"bytes"
	"fmt"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

// ==================================================================
// GroupChatMessagesIndex
// ==================================================================

func (bav *UtxoView) getGroupChatMessagesIndex(groupChatMessageKey GroupChatMessageKey) *MessageEntry {
	mapValue, existsMapValue := bav.GroupChatMessagesIndex[groupChatMessageKey]
	if existsMapValue {
		return mapValue
	}

	dbMessageEntry := DBGetGroupChatMessagesIndex(bav.Handle, bav.Snapshot, groupChatMessageKey)
	if dbMessageEntry != nil {
		bav.setGroupChatMessagesIndex(dbMessageEntry)
	}
	return dbMessageEntry
}

func (bav *UtxoView) setGroupChatMessagesIndex(messageEntry *MessageEntry) {
	groupChatMessageKey, err := MakeGroupChatMessageKeyFromMessageEntry(messageEntry)
	if err != nil {
		glog.Errorf("setGroupChatMessagesIndex: Error making group chat message key: %v", err)
		return
	}

	bav.GroupChatMessagesIndex[groupChatMessageKey] = messageEntry
}

func (bav *UtxoView) deleteGroupChatMessagesIndex(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	// As opposed to the setGroupChatMessagesIndex, we only need to do *the delete* once.
	// This is because set will delete both entries at once.
	bav.setGroupChatMessagesIndex(&tombstoneMessageEntry)
}

// ==================================================================
// DmThreadIndex
// ==================================================================

func (bav *UtxoView) getDmThreadIndex(dmThreadKey DmThreadKey) *MessageEntry {
	mapValue, existsMapValue := bav.DmThreadIndex[dmThreadKey]
	if existsMapValue {
		return mapValue
	}

	dbMessageEntry := DBGetDmThreadEntry(bav.Handle, bav.Snapshot, dmThreadKey)
	if dbMessageEntry != nil {
		bav.setDmThreadIndex(dbMessageEntry, false)
	}
	return dbMessageEntry
}

func (bav *UtxoView) setDmThreadIndex(messageEntry *MessageEntry, shouldReverse bool) {
	dmThreadKey, err := MakeDmThreadKeyFromMessageEntry(messageEntry, shouldReverse)
	if err != nil {
		glog.Errorf("setDmThreadIndex: Error making dm thread key: %v", err)
		return
	}
	bav.DmThreadIndex[dmThreadKey] = messageEntry
}

func (bav *UtxoView) deleteDmThreadIndex(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	// We delete both entries at once.
	bav.setDmThreadIndex(&tombstoneMessageEntry, false)
	bav.setDmThreadIndex(&tombstoneMessageEntry, true)
}

// ==================================================================
// DmMessagesIndex
// ==================================================================

func (bav *UtxoView) getDmMessagesIndex(dmMessageKey DmMessageKey) *MessageEntry {
	mapValue, existsMapValue := bav.DmMessagesIndex[dmMessageKey]
	if existsMapValue {
		return mapValue
	}

	dbMessageEntry := DBGetDmMessageEntry(bav.Handle, bav.Snapshot, dmMessageKey)
	if dbMessageEntry != nil {
		bav.setDmMessageIndex(dbMessageEntry)
	}
	return dbMessageEntry
}

func (bav *UtxoView) setDmMessageIndex(messageEntry *MessageEntry) {
	dmMessageKey, err := MakeDmMessageKeyFromMessageEntry(messageEntry)
	if err != nil {
		glog.Errorf("setDmMessageIndex: Error making dm message key: %v", err)
		return
	}
	bav.DmMessagesIndex[dmMessageKey] = messageEntry
}

func (bav *UtxoView) deleteDmMessageIndex(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	// As opposed to the setDmMessageIndex, we only need to do *the delete* once.
	// This is because set will delete both entries at once.
	bav.setDmMessageIndex(&tombstoneMessageEntry)
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

	// Check the lenght of the EncryptedText
	if uint64(len(txMeta.EncryptedText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageEncryptedTextLengthExceedsMax, "_connectNewMessage: "+
				"EncryptedText length (%d) exceeds max length (%d)",
			len(txMeta.EncryptedText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.SenderAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ",
			"SenderAccessGroupOwnerPublicKey and SenderAccessGroupKeyName are invalid")
	}

	if !bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageMessageSenderDoesNotMatchTxnPublicKey, "_connectNewMessage: "+
				"SenderAccessGroupOwnerPublicKey (%v) does not match txn.PublicKey (%v)",
			PkToString(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), bav.Params),
			PkToString(txn.PublicKey, bav.Params))
	}

	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.RecipientAccessGroupKeyName.ToBytes(), txMeta.RecipientAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ",
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

	messageEntry := &MessageEntry{
		SenderPublicKey:             &txMeta.SenderAccessGroupOwnerPublicKey,
		RecipientPublicKey:          &txMeta.RecipientAccessGroupOwnerPublicKey,
		EncryptedText:               txMeta.EncryptedText,
		TstampNanos:                 txMeta.TimestampNanos,
		Version:                     MessagesVersion3,
		SenderMessagingPublicKey:    &txMeta.SenderAccessPublicKey,
		SenderAccessGroupKeyName:    &txMeta.SenderAccessGroupKeyName,
		RecipientMessagingPublicKey: &txMeta.RecipientAccessPublicKey,
		RecipientAccessGroupKeyName: &txMeta.RecipientAccessGroupKeyName,
		ExtraData:                   mergeExtraData(nil, txn.ExtraData),
	}

	switch txMeta.MessageType {
	case MessageTypeDm:
		// TODO: Once access group utxo_view logic is finalized, verify that the message fulfills DM criteria.
		var dmThreadMessageEntry, dmThreadReverse, copyDmThreadMessageEntry *MessageEntry
		dmThreadKey, err := MakeDmThreadKeyFromMessageEntry(messageEntry, false)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ")
		}
		dmThreadMessageEntry = bav.getDmThreadIndex(dmThreadKey)
		if dmThreadMessageEntry != nil && !dmThreadMessageEntry.isDeleted {
			tempDmThread := *dmThreadMessageEntry
			copyDmThreadMessageEntry = &tempDmThread
		}
		dmThreadKeyReverse, err := MakeDmThreadKeyFromMessageEntry(messageEntry, true)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ")
		}
		dmThreadReverse = bav.getDmThreadIndex(dmThreadKey)
		if dmThreadMessageEntry != nil && !dmThreadMessageEntry.isDeleted {
			blockHeightUint64 := uint64(blockHeight)
			if !reflect.DeepEqual(EncodeToBytes(blockHeightUint64, dmThreadMessageEntry), EncodeToBytes(blockHeightUint64, dmThreadReverse)) {
				glog.Errorf("_connectNewMessage: DM thread and DM thread reverse are not equal: "+
					"dmThreadKey: %v, dmThreadKeyReverse: %v, dmThreadMessageEntry: %v, dmThreadReverse: %v",
					dmThreadKey, dmThreadKeyReverse, dmThreadMessageEntry, dmThreadReverse)
			}
		}
		dmMessageKey, err := MakeDmMessageKeyFromMessageEntry(messageEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ")
		}
		dmMessage := bav.getDmMessagesIndex(dmMessageKey)
		if dmMessage != nil || !dmMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageDmMessageAlreadyExists,
				"_connectNewMessage: DM thread already exists for sender (%v) and recipient (%v)",
				txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey)
		}

		bav.setDmThreadIndex(messageEntry, false)
		bav.setDmThreadIndex(messageEntry, true)
		bav.setDmMessageIndex(messageEntry)
		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:              OperationTypeNewMessage,
			PrevDmThreadIndex: copyDmThreadMessageEntry,
			DmThreadKey:       dmThreadKey,
			DmMessageIndexKey: dmMessageKey,
			MessageType:       MessageTypeDm,
		})

	case MessageTypeGroupChat:
		// TODO: Once access group utxo_view logic is finalized, verify that the message fulfills Group Chat criteria.
		var groupChatMessage *MessageEntry
		groupChatMessageKey, err := MakeGroupChatMessageKeyFromMessageEntry(messageEntry)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: ")
		}
		groupChatMessage = bav.getGroupChatMessagesIndex(groupChatMessageKey)
		if groupChatMessage != nil || !groupChatMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageGroupChatMessageAlreadyExists,
				"_connectNewMessage: Group chat thread already exists for recipient (%v)",
				txMeta.RecipientAccessGroupOwnerPublicKey)
		}
		bav.setGroupChatMessagesIndex(messageEntry)

		utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
			Type:                 OperationTypeNewMessage,
			GroupChatMessagesKey: groupChatMessageKey,
			MessageType:          MessageTypeGroupChat,
		})
	}

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
	_ = txMeta
	messageType := prevUtxoOp.MessageType

	switch messageType {
	case MessageTypeDm:
		if prevUtxoOp.PrevDmThreadIndex == nil {
			currentDmThreadIndex := bav.getDmThreadIndex(prevUtxoOp.DmThreadKey)
			if currentDmThreadIndex != nil && !currentDmThreadIndex.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: DM thread is already deleted or does not exist "+
					"dmThreadKey: %v", prevUtxoOp.DmThreadKey)
			}
			if currentDmThreadIndex != nil && !currentDmThreadIndex.isDeleted {
				bav.deleteDmThreadIndex(currentDmThreadIndex)
			}
		} else {
			currentDmThreadIndex := bav.getDmThreadIndex(prevUtxoOp.DmThreadKey)
			bav.deleteDmThreadIndex(currentDmThreadIndex)
			// Set the previous DM thread index.
			bav.setDmThreadIndex(prevUtxoOp.PrevDmThreadIndex, false)
			bav.setDmThreadIndex(prevUtxoOp.PrevDmThreadIndex, true)
		}

		// Delete the DM message, there is no prev entry for messages so we don't need to re-set it.
		currentDmMessage := bav.getDmMessagesIndex(prevUtxoOp.DmMessageIndexKey)
		if currentDmMessage == nil || currentDmMessage.isDeleted {
			return fmt.Errorf("_disconnectNewMessage: DM message is already deleted or does not exist "+
				"dmMessageKey: %v", prevUtxoOp.DmMessageIndexKey)
		}
		bav.deleteDmMessageIndex(currentDmMessage)
	case MessageTypeGroupChat:
		// Delete the group chat message, there is no prev entry for messages so we don't need to re-set it.
		currentGroupChatMessage := bav.getGroupChatMessagesIndex(prevUtxoOp.GroupChatMessagesKey)
		bav.deleteGroupChatMessagesIndex(currentGroupChatMessage)
	}

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
