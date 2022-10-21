package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"reflect"
)

// ==================================================================
// MessageKeyToMessageEntry
// ==================================================================

func (bav *UtxoView) _getMessageEntryForMessageKey(messageKey *MessageKey) *MessageEntry {
	if messageKey == nil {
		glog.Errorf("_getMessageEntryForMessageKey: Called with nil messageKey; " +
			"this should never happen.")
		return nil
	}
	// It is important to note that this function has to be called with a MessageKey
	// that's set with *access keys* rather than user keys.

	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.MessageKeyToMessageEntry[*messageKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	dbMessageEntry := DBGetMessageEntry(bav.Handle, bav.Snapshot, messageKey.PublicKey[:], messageKey.TstampNanos)
	if dbMessageEntry != nil {
		bav._setMessageEntryMappings(dbMessageEntry)
	}
	return dbMessageEntry
}

func (bav *UtxoView) _setMessageEntryMappings(messageEntry *MessageEntry) {
	// This function shouldn't be called with nil.
	if messageEntry == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil MessageEntry; " +
			"this should never happen.")
		return
	}

	if messageEntry.SenderAccessPublicKey == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil SenderAccessPublicKey; " +
			"this should never happen.")
		return
	}
	if messageEntry.RecipientAccessPublicKey == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil RecipientAccessPublicKey; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the sender and the recipient.
	// We index messages by sender and recipient access public keys. Group chats add access keys for
	// each recipient. As a result, when fetching user messages, we will need to fetch messages for each
	// access key. Indexing by access keys instead of user main keys transpired to be more efficient.
	senderKey := MakeMessageKey(messageEntry.SenderAccessPublicKey[:], messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[senderKey] = messageEntry

	recipientKey := MakeMessageKey(messageEntry.RecipientAccessPublicKey[:], messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[recipientKey] = messageEntry
}

func (bav *UtxoView) _deleteMessageEntryMappings(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	// As opposed to the _setMessageEntryMappings, we only need to do *the delete* once.
	// This is because set will delete both entries at once.
	bav._setMessageEntryMappings(&tombstoneMessageEntry)
}

// ==================================================================
// MessageMap
// ==================================================================

func (bav *UtxoView) getMessage(messageHash *BlockHash) *PGMessage {
	mapValue, existsMapValue := bav.MessageMap[*messageHash]
	if existsMapValue {
		return mapValue
	}

	message := bav.Postgres.GetMessage(messageHash)
	if message != nil {
		bav.setMessageMappings(message)
	}
	return message
}

// TODO: Update for Postgres
func (bav *UtxoView) GetMessagesForUser(publicKey []byte, blockHeight uint32) (
	_messageEntries []*MessageEntry, _accessKeyEntries []*AccessGroupEntry, _err error) {

	return bav.GetLimitedMessagesForUser(publicKey, math.MaxUint64, blockHeight)
}

// TODO: Update for Postgres
func (bav *UtxoView) GetLimitedMessagesForUser(ownerPublicKey []byte, limit uint64, blockHeight uint32) (
	_messageEntries []*MessageEntry, _accessGroupEntries []*AccessGroupEntry, _err error) {

	// This function will fetch up to limit number of messages for a public key. To accomplish
	// this, we will have to fetch messages for each groups that the user has registered.

	// First get all access keys for a user.
	accessGroupEntries, err := bav.GetAccessGroupEntriesForUser(ownerPublicKey, blockHeight)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetLimitedMessagesForUser: "+
			"problem getting user access keys")
	}

	// We define an auxiliary map to keep track of messages in UtxoView and DB.
	messagesMap := make(map[MessageKey]*MessageEntry)

	// First look for messages in the UtxoView. We don't skip deleted entries for now as we will do it later.
	for messageKey, messageEntry := range bav.MessageKeyToMessageEntry {
		for _, accessKeyEntry := range accessGroupEntries {
			if reflect.DeepEqual(messageKey.PublicKey[:], accessKeyEntry.AccessPublicKey[:]) {
				// We will add the messages with the sender access public key as the MessageKey
				// so that we have no overlaps in the DB in some weird edge cases.
				mapKey := MakeMessageKey(messageEntry.SenderAccessPublicKey[:], messageEntry.TstampNanos)
				messagesMap[mapKey] = messageEntry
				break
			}
		}
	}

	// We fetched all UtxoView entries, so now look for messages in the DB.
	dbMessageEntries, err := DBGetLimitedMessageForAccessKeys(bav.Handle, accessGroupEntries, limit)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntries from db: ")
	}
	// Now iterate through all the db message entries and add them to our auxiliary map.
	for _, messageEntry := range dbMessageEntries {
		// Use the sender access public key for the MessageKey to make sure they match the UtxoView entries.
		mapKey := MakeMessageKey(messageEntry.SenderAccessPublicKey[:], messageEntry.TstampNanos)
		if _, exists := messagesMap[mapKey]; !exists {
			messagesMap[mapKey] = messageEntry
		}
	}

	// We have added all message entries to our auxiliary map so now we transform them into a map.
	var messageEntries []*MessageEntry
	for _, messageEntry := range messagesMap {
		// Skip isDeleted entries
		if messageEntry.isDeleted {
			continue
		}
		messageEntries = append(messageEntries, messageEntry)
	}
	return messageEntries, accessGroupEntries, nil
}

func (bav *UtxoView) setMessageMappings(message *PGMessage) {
	bav.MessageMap[*message.MessageHash] = message
}

func (bav *UtxoView) deleteMessageMappings(message *PGMessage) {
	deletedMessage := *message
	deletedMessage.isDeleted = true
	bav.setMessageMappings(&deletedMessage)
}

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

func ReadMessageVersion(txn *MsgDeSoTxn) (_version uint8, _err error) {
	if txn == nil {
		return 0, fmt.Errorf("ReadMessageVersion: Called with nil MsgDeSoTxn")
	}

	// Check the version of the message by looking at the MessagesVersionString field in ExtraData.
	var version uint64
	var err error
	if extraV, hasExtraV := txn.ExtraData[MessagesVersionString]; hasExtraV {
		rr := bytes.NewReader(extraV)
		version, err = ReadUvarint(rr)
		if err != nil {
			return 0, errors.Wrapf(RuleErrorPrivateMessageInvalidVersion,
				"ReadMessageVersion: Problem reading message version from ExtraData, error: (%v)", err)
		}
		if version < 0 || version > MessagesVersion3 {
			return 0, errors.Wrapf(RuleErrorPrivateMessageInvalidVersion,
				"ReadMessageVersion: Problem reading message version from ExtraData, expecting version "+
					"between <1, 3> but got (%v)", version)
		}
	}
	return uint8(version), nil
}

func (bav *UtxoView) _connectPrivateMessage(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypePrivateMessage {
		return 0, 0, nil, fmt.Errorf("_connectPrivateMessage: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*PrivateMessageMetadata)

	// Check the length of the EncryptedText
	if uint64(len(txMeta.EncryptedText)) > bav.Params.MaxPrivateMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageEncryptedTextLengthExceedsMax, "_connectPrivateMessage: "+
				"EncryptedTextLen = %d; Max length = %d",
			len(txMeta.EncryptedText), bav.Params.MaxPrivateMessageLengthBytes)
	}

	// Check that a proper public key is provided in the message metadata
	if err := IsByteArrayValidPublicKey(txMeta.RecipientPublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageParsePubKeyError, "_connectPrivateMessage: Parse error: %v", err)
	}

	// Check that the timestamp is greater than zero. Not doing this could make
	// the message not get returned when we call Seek() in our db. It's also just
	// a reasonable sanity check.
	if txMeta.TimestampNanos == 0 {
		return 0, 0, nil, RuleErrorPrivateMessageTstampIsZero
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: ")
	}

	// At this point the inputs and outputs have been processed. Now we
	// need to handle the metadata.

	// Read the message version from ExtraData
	version, err := ReadMessageVersion(txn)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: ")
	}

	// If we're past the ExtraData block height then merge the extraData in from the
	// txn ExtraData.
	var extraData map[string][]byte
	if blockHeight >= bav.Params.ForkHeights.ExtraDataOnEntriesBlockHeight {
		// There's no previous entry to look up for messages
		extraData = mergeExtraData(nil, txn.ExtraData)
	}

	// Create a MessageEntry, we do this now because we might modify some of the fields
	// based on the version of the message.
	messageEntry := &MessageEntry{
		SenderPublicKey:             NewPublicKey(txn.PublicKey),
		RecipientPublicKey:          NewPublicKey(txMeta.RecipientPublicKey),
		EncryptedText:               txMeta.EncryptedText,
		TstampNanos:                 txMeta.TimestampNanos,
		Version:                     version,
		SenderAccessPublicKey:       NewPublicKey(txn.PublicKey),
		SenderAccessGroupKeyName:    BaseGroupKeyName(),
		RecipientAccessPublicKey:    NewPublicKey(txMeta.RecipientPublicKey),
		RecipientAccessGroupKeyName: BaseGroupKeyName(),
		ExtraData:                   extraData,
	}

	// If message was encrypted using DeSo V3 Messages, we will look for access keys in
	// ExtraData. V3 allows users to register access keys on-chain, and encrypt messages
	// to these access keys, as opposed to encrypting messages to user's main keys.
	if version == MessagesVersion3 {
		// Make sure DeSo V3 messages are live.
		if blockHeight < bav.Params.ForkHeights.DeSoV3MessagesBlockHeight {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageAccessPartyBeforeBlockHeight,
				"_connectPrivateMessage: access party used before block height")
		}
		// Look for access keys in transaction ExtraData
		// TODO: Do we want to make the ExtraData keys shorter to save space and transaction cost?
		if txn.ExtraData == nil {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageMissingExtraData,
				"_connectPrivateMessage: ExtraData cannot be nil")
		}
		senderAccessPublicKey, existsSender := txn.ExtraData[SenderAccessPublicKey]
		recipientAccessPublicKey, existsRecipient := txn.ExtraData[RecipientAccessPublicKey]
		// At least one of these fields must exist if this is a V3 message.
		if !existsSender && !existsRecipient {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageSentWithoutProperAccessParty,
				"_connectPrivateMessage: at least one access party must be present")
		}

		// We will now proceed to add sender's and recipient's access keys to the message entry.
		// We make sure that both sender public key and key name is present in transaction's ExtraData.
		senderAccessKeyName, existsSenderName := txn.ExtraData[SenderAccessGroupKeyName]
		if existsSender && existsSenderName {
			// Validate the key and the name using this helper function to make sure access key has been previously authorized.
			if err = bav.ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView(
				txn.PublicKey, senderAccessPublicKey, senderAccessKeyName, blockHeight); err != nil {
				return 0, 0, nil, errors.Wrapf(RuleErrorPrivateMessageFailedToValidateAccessKey,
					"_connectPrivateMessage: failed to validate public key and key name")
			}
			// If everything went well, update the access key information in the message entry.
			messageEntry.SenderAccessPublicKey = NewPublicKey(senderAccessPublicKey)
			messageEntry.SenderAccessGroupKeyName = NewGroupKeyName(senderAccessKeyName)
		}
		// We do an analogous validation for the recipient's access key.
		recipientAccessKeyName, existsRecipientName := txn.ExtraData[RecipientAccessGroupKeyName]
		if existsRecipient && existsRecipientName {
			if err := bav.ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView(
				txMeta.RecipientPublicKey, recipientAccessPublicKey, recipientAccessKeyName, blockHeight); err != nil {
				return 0, 0, nil, errors.Wrapf(RuleErrorPrivateMessageFailedToValidateAccessKey,
					"_connectPrivateMessage: failed to validate public key and key name, error: (%v)", err)
			}
			// If everything worked, update the access key information in the message entry.
			messageEntry.RecipientAccessPublicKey = NewPublicKey(recipientAccessPublicKey)
			messageEntry.RecipientAccessGroupKeyName = NewGroupKeyName(recipientAccessKeyName)
		}

		// After the DeSoAccessGroupsBlockHeight block height we force the usage of V3 messages.
		if blockHeight >= bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
			if !(existsSender && existsSenderName && existsRecipient && existsRecipientName) {
				return 0, 0, nil, errors.Wrapf(
					RuleErrorPrivateMessageSentWithoutProperAccessParty,
					"_connectPrivateMessage: SenderKey, SenderName, RecipientKey, RecipientName should all exist "+
						"in ExtraData after DeSoAccessGroupsBlockHeight.")
			}
			// Reject message if sender is muted
			senderAccessPk := NewPublicKey(senderAccessPublicKey)
			// txMeta.RecipientPublicKey is the GroupOwnerPublicKey in disguise
			groupOwnerAccessPk := NewPublicKey(txMeta.RecipientPublicKey)
			accessGroupKeyName := NewGroupKeyName(recipientAccessKeyName)
			// check if sender is muted
			attributeEntry, err := bav.GetGroupMemberAttributeEntry(groupOwnerAccessPk, accessGroupKeyName, senderAccessPk, AccessGroupMemberAttributeIsMuted)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: Problem checking if sender is muted")
			}
			if attributeEntry != nil && attributeEntry.IsSet == true {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessMemberMuted,
					"_connectPrivateMessage: Sender is muted")
			}
		}
	}

	// Make sure we don't try to send messages between identical access public keys.
	// We don't allow groups to send messages to themselves; however, a user is allowed to send a message to himself.
	// This would happen if we set SenderPublicKey == RecipientPublicKey. This could be used as a "saved messages" feature.
	if reflect.DeepEqual(messageEntry.SenderAccessPublicKey[:], messageEntry.RecipientAccessPublicKey[:]) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey,
			"_connectPrivateMessage: Parse error: %v", err)
	}

	// If a message already exists and does not have isDeleted=true then return
	// an error. In general, messages must have unique (pubkey, tstamp) tuples.
	//
	// Postgres does not enforce these rule errors
	if bav.Postgres == nil {
		// We fetch an entry both for the recipient and the sender. It is worth noting that we're indexing
		// private messages by the access public keys, rather than sender/owner main keys. This is
		// particularly useful in group messages, and allows us to later fetch messages from DB more efficiently.
		senderMessageKey := MakeMessageKey(messageEntry.SenderAccessPublicKey[:], txMeta.TimestampNanos)
		senderMessage := bav._getMessageEntryForMessageKey(&senderMessageKey)
		if senderMessage != nil && !senderMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &senderMessageKey)
		}
		recipientMessageKey := MakeMessageKey(messageEntry.RecipientAccessPublicKey[:], txMeta.TimestampNanos)
		recipientMessage := bav._getMessageEntryForMessageKey(&recipientMessageKey)
		if recipientMessage != nil && !recipientMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithRecipientPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &recipientMessageKey)
		}
	}

	if verifySignatures {
		// _connectBasicTransfer has already checked that the transaction is
		// signed by the top-level public key, which we take to be the sender's
		// public key so there is no need to verify anything further.
	}

	// At this point we are confident that we are parsing a message with a unique
	// <OwnerPublicKey, TstampNanos> tuple. We also know that the sender and recipient
	// have different public keys.

	if bav.Postgres != nil {
		//TODO: Fix Postgres
		message := &PGMessage{
			MessageHash:        txn.Hash(),
			SenderPublicKey:    txn.PublicKey,
			RecipientPublicKey: txMeta.RecipientPublicKey,
			EncryptedText:      txMeta.EncryptedText,
			TimestampNanos:     txMeta.TimestampNanos,
			ExtraData:          extraData,
		}

		bav.setMessageMappings(message)
	} else {
		// Set the mappings in our in-memory map for the MessageEntry.
		bav._setMessageEntryMappings(messageEntry)
	}

	// Add an operation to the list at the end indicating we've added a message
	// to our data structure.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypePrivateMessage,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// TODO: Update for postgres
func (bav *UtxoView) _disconnectPrivateMessage(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a PrivateMessage operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectPrivateMessage: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypePrivateMessage {
		return fmt.Errorf("_disconnectPrivateMessage: Trying to revert "+
			"OperationTypePrivateMessage but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is PrivateMessage
	txMeta := currentTxn.TxnMeta.(*PrivateMessageMetadata)

	// Check for the message version in transaction's ExtraData.
	version, err := ReadMessageVersion(currentTxn)
	if err != nil {
		return errors.Wrapf(err, "_disconnectPrivateMessage: ")
	}

	// We keep track of sender and recipient access public keys. We will update them in V3 messages.
	senderPkBytes := currentTxn.PublicKey
	recipientPkBytes := txMeta.RecipientPublicKey

	// Do some sanity-checks when message is V3.
	if version == MessagesVersion3 {
		if currentTxn.ExtraData == nil {
			return errors.Wrapf(RuleErrorPrivateMessageMissingExtraData,
				"_disconnectPrivateMessage: ExtraData cannot be nil")
		}
		senderAccessPublicKey, existsSender := currentTxn.ExtraData[SenderAccessPublicKey]
		recipientAccessPublicKey, existsRecipient := currentTxn.ExtraData[RecipientAccessPublicKey]
		// At least one of these fields must exist.
		if !existsSender && !existsRecipient {
			return errors.Wrapf(RuleErrorPrivateMessageSentWithoutProperAccessParty,
				"_disconnectPrivateMessage: at least one access party must be present")
		}
		if existsSender {
			if err := IsByteArrayValidPublicKey(senderAccessPublicKey); err != nil {
				return errors.Wrapf(RuleErrorPrivateMessageSentWithoutProperAccessParty,
					"_disconnectPrivateMessage: at least one access party must be present")
			}
			senderPkBytes = senderAccessPublicKey
		}
		if existsRecipient {
			if err := IsByteArrayValidPublicKey(recipientAccessPublicKey); err != nil {
				return errors.Wrapf(RuleErrorPrivateMessageSentWithoutProperAccessParty,
					"_disconnectPrivateMessage: at least one access party must be present")
			}
			recipientPkBytes = recipientAccessPublicKey
		}
	}

	// Get the entry from the UtxoView and verify it wasn't already deleted. There are two
	// entries, one for the sender and one for the recipient, but for now let's only validate
	// the sender's entry.
	senderMessageKey := MakeMessageKey(senderPkBytes, txMeta.TimestampNanos)
	senderMessageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if senderMessageEntry == nil || senderMessageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&senderMessageKey, senderMessageEntry)
	}

	// Verify that the sender and recipient in the entry match the TxnMeta as a sanity-check.
	if !reflect.DeepEqual(senderMessageEntry.SenderPublicKey[:], currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Sender public key on "+
			"MessageEntry was %s but the OwnerPublicKey on the txn was %s",
			PkToString(senderMessageEntry.SenderPublicKey[:], bav.Params),
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(senderMessageEntry.RecipientPublicKey[:], txMeta.RecipientPublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Recipient public key on "+
			"MessageEntry was %s but the OwnerPublicKey on the TxnMeta was %s",
			PkToString(senderMessageEntry.RecipientPublicKey[:], bav.Params),
			PkToString(txMeta.RecipientPublicKey, bav.Params))
	}
	// Sanity-check that the MessageEntry TstampNanos matches the transaction.
	if senderMessageEntry.TstampNanos != txMeta.TimestampNanos {
		return fmt.Errorf("_disconnectPrivateMessage: TimestampNanos in "+
			"MessageEntry was %d but in transaction it was %d",
			senderMessageEntry.TstampNanos,
			txMeta.TimestampNanos)
	}
	// Sanity-check that the EncryptedText on the MessageEntry matches the transaction
	// just for good measure.
	if !reflect.DeepEqual(senderMessageEntry.EncryptedText, txMeta.EncryptedText) {
		return fmt.Errorf("_disconnectPrivateMessage: EncryptedText in MessageEntry "+
			"did not match EncryptedText in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.EncryptedText),
			hex.EncodeToString(txMeta.EncryptedText))
	}

	// Sanity-check V3 data such as sender and recipient access public keys.
	// In DeSo V3 Messages, all message entries have these fields.
	if !reflect.DeepEqual(senderMessageEntry.SenderAccessPublicKey[:], senderPkBytes) {
		return fmt.Errorf("_disconnectPrivateMessage: sender access public key in MessageEntry "+
			"did not match the public key in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.SenderAccessPublicKey[:]),
			hex.EncodeToString(senderPkBytes))
	}

	if !reflect.DeepEqual(senderMessageEntry.RecipientAccessPublicKey[:], recipientPkBytes) {
		return fmt.Errorf("_disconnectPrivateMessage: sender access public key in MessageEntry "+
			"did not match the public key in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.RecipientAccessPublicKey[:]),
			hex.EncodeToString(recipientPkBytes))
	}

	// We passed all sanity checks so now fetch the recipient entry and make sure it wasn't deleted.
	recipientMessageKey := MakeMessageKey(recipientPkBytes, txMeta.TimestampNanos)
	recipientMessageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if recipientMessageEntry == nil || recipientMessageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry (%v) for "+
			"RecipientMessageKey (%v) was found to be nil or deleted",
			recipientMessageEntry, &recipientMessageKey)
	}

	// Make sure the sender and recipient entries are identical by comparing their byte encodings.
	if !reflect.DeepEqual(EncodeToBytes(uint64(blockHeight), recipientMessageEntry),
		EncodeToBytes(uint64(blockHeight), senderMessageEntry)) {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"sender (%v) doesn't matche the entry for the recipient (%v)",
			senderMessageEntry, recipientMessageEntry)
	}

	// If we got here then we passed all sanity checks, and we're ready to delete the private message entries.

	// Now that we are confident the MessageEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this message.
	// Both entries will be deleted at the same time.
	bav._deleteMessageEntryMappings(senderMessageEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the PrivateMessage operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
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

	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.RecipientAccessGroupKeyName.ToBytes(), txMeta.RecipientAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
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

	messageEntry := &MessageEntry{
		SenderPublicKey:             &txMeta.SenderAccessGroupOwnerPublicKey,
		RecipientPublicKey:          &txMeta.RecipientAccessGroupOwnerPublicKey,
		EncryptedText:               txMeta.EncryptedText,
		TstampNanos:                 txMeta.TimestampNanos,
		Version:                     MessagesVersion3,
		SenderAccessPublicKey:       &txMeta.SenderAccessPublicKey,
		SenderAccessGroupKeyName:    &txMeta.SenderAccessGroupKeyName,
		RecipientAccessPublicKey:    &txMeta.RecipientAccessPublicKey,
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
