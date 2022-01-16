package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"math"
	"reflect"
)

func (bav *UtxoView) _getMessageEntryForMessageKey(messageKey *MessageKey) *MessageEntry {
	// It is important to note that this function has to be called with a MessageKey
	// that's set with *messaging keys* rather than user keys.

	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.MessageKeyToMessageEntry[*messageKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	dbMessageEntry := DBGetMessageEntry(bav.Handle, messageKey.PublicKey[:], messageKey.TstampNanos)
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

	// Add a mapping for the sender and the recipient.
	// We index messages by sender and recipient messaging public keys. Group chats add messaging keys for
	// each recipient. As a result, when fetching user messages, we will need to fetch messages for each
	// messaging key. Indexing by messaging keys instead of user main keys transpired to be more efficient.
	senderKey := MakeMessageKey(messageEntry.SenderMessagingPublicKey[:], messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[senderKey] = messageEntry

	recipientKey := MakeMessageKey(messageEntry.RecipientMessagingPublicKey[:], messageEntry.TstampNanos)
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

func (bav *UtxoView) GetMessagingKeyToMessagingKeyEntryMapping(messagingKey *MessagingKey) *MessagingKeyEntry {
	// This function is used to get a MessagingKeyEntry given a MessagingKey. The V3 messages are
	// backwards-compatible, and in particular each user has a built-in messaging key, called the
	// "base key," which is simply a messaging key corresponding to user's main key.
	if EqualKeyName(&messagingKey.KeyName, BaseKeyName()) {
		return &MessagingKeyEntry{
			MessagingPublicKey: NewPublicKey(messagingKey.PublicKey[:]),
			MessagingKeyName:   BaseKeyName(),
		}
	}

	// If an entry exists in the in-memory map, return the value of that mapping.
	if mapValue, exists := bav.MessagingKeyToMessagingKeyEntry[*messagingKey]; exists {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory UtxoView mapping.
	messagingKeyEntry := DBGetMessagingKeyEntry(bav.Handle, messagingKey)
	if messagingKeyEntry != nil {
		bav._setMessagingKeyToMessagingKeyEntryMapping(&messagingKey.PublicKey, messagingKeyEntry)
	}
	return messagingKeyEntry
}

func (bav *UtxoView) _setMessagingKeyToMessagingKeyEntryMapping(ownerPublicKey *PublicKey,
	messagingKeyEntry *MessagingKeyEntry) {

	// This function shouldn't be called with a nil entry.
	if messagingKeyEntry == nil {
		glog.Errorf("_setMessagingKeyToMessagingKeyEntryMapping: Called with nil MessagingKeyEntry; " +
			"this should never happen.")
		return
	}

	// Create a key for the UtxoView mapping. We always put user's main public key as part of the map key.
	// Note that this is different from message entries, which are indexed by messaging public keys.
	messagingKey := MessagingKey{
		PublicKey: *ownerPublicKey,
		KeyName:   *messagingKeyEntry.MessagingKeyName,
	}
	bav.MessagingKeyToMessagingKeyEntry[messagingKey] = messagingKeyEntry
}

func (bav *UtxoView) _deleteMessagingKeyToMessagingKeyEntryMapping(ownerPublicKey *PublicKey,
	messagingKeyEntry *MessagingKeyEntry) {

	// Create a tombstone entry.
	tombstoneMessageKeyEntry := *messagingKeyEntry
	tombstoneMessageKeyEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessagingKeyToMessagingKeyEntryMapping(ownerPublicKey, &tombstoneMessageKeyEntry)
}

//
// Postgres messages
//

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

func (bav *UtxoView) setMessageMappings(message *PGMessage) {
	bav.MessageMap[*message.MessageHash] = message
}

func (bav *UtxoView) deleteMessageMappings(message *PGMessage) {
	deletedMessage := *message
	deletedMessage.isDeleted = true
	bav.setMessageMappings(&deletedMessage)
}

func (bav *UtxoView) GetUserMessagingKeys(publicKey []byte) (
	_messagingKeyEntries []*MessagingKeyEntry, _err error) {
	// This function will return all messaging keys of a user, including the base key,
	// messaging keys, and all recipient keys.

	// This is our helper map to keep track of all user messaging keys.
	messagingKeysMap := make(map[PublicKey]*MessagingKeyEntry)

	// Start by fetching all the messaging keys that we have in the UtxoView.
	for messagingKey, messagingKeyEntry := range bav.MessagingKeyToMessagingKeyEntry {
		// We don't check for deleted entries now, we will do that later once we add messaging keys
		// from the DB. For now we also omit the base key, we will add it later when querying the DB.

		// Check if the messaging key corresponds to our public key.
		if reflect.DeepEqual(messagingKey.PublicKey, publicKey) {
			messagingKeysMap[*messagingKeyEntry.MessagingPublicKey] = messagingKeyEntry
			continue
		}
		// Now we will look for messaging keys where the public key is a recipient of a group chat.
		for _, recipient := range messagingKeyEntry.Recipients {
			if reflect.DeepEqual(recipient.RecipientPublicKey[:], publicKey) {
				// If user is a recipient of a group chat, we need to add a modified messaging entry.
				messagingKeysMap[*messagingKeyEntry.MessagingPublicKey] = messagingKeyEntry
				break
			}
		}
	}

	// We fetched all the entries from the UtxoView, so we move to the DB.
	dbMessagingKeys, err := DBGetAllUserMessagingKeys(bav.Handle, publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetUserMessagingKeys: problem getting " +
			"messaging keys from the DB")
	}
	// Now go through the messaging keys in the DB and add keys we haven't seen before.
	for _, messagingKeyEntry := range dbMessagingKeys {
		key := *messagingKeyEntry.MessagingPublicKey
		// Check if we have seen the messaging key before.
		if _, exists := messagingKeysMap[key]; !exists {
			messagingKeysMap[key] = messagingKeyEntry
		} else {
			// If the messaging key was deleted in the UtxoView, we can now delete it from our map.
			if messagingKeysMap[key].isDeleted {
				delete(messagingKeysMap, key)
			}
		}
	}

	// We have all the user's messaging keys in our map, so we now turn them into a list.
	for _, messagingKeyEntry := range messagingKeysMap {
		_messagingKeyEntries = append(_messagingKeyEntries, messagingKeyEntry)
	}
	return _messagingKeyEntries, nil
}

// TODO: Update for Postgres
func (bav *UtxoView) GetMessagesForUser(publicKey []byte) (
	_messageEntries []*MessageEntry, _messagingKeyEntries []*MessagingKeyEntry, _err error) {

	return bav.GetLimitedMessagesForUser(publicKey, math.MaxUint64)
}

// TODO: Update for Postgres
func (bav *UtxoView) GetLimitedMessagesForUser(publicKey []byte, limit uint64) (
	_messageEntries []*MessageEntry, _messagingKeyEntries []*MessagingKeyEntry, _err error) {

	// This function will fetch up to limit number of messages for a public key. To accomplish
	// this, we will have to fetch messages for each messaging key that the user has registered.

	// First get all messaging keys for a user.
	var err error
	_messagingKeyEntries, err = bav.GetUserMessagingKeys(publicKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetLimitedMessagesForUser: " +
			"problem getting user messaging keys")
	}

	// We define an auxiliary map to keep track of messages in UtxoView and DB.
	messagesMap := make(map[MessageKey]*MessageEntry)

	// First look for messages in the UtxoView. We don't skip deleted entries for now as we will do it later.
	for messageKey, messageEntry := range bav.MessageKeyToMessageEntry {
		for _, messagingKeyEntry := range _messagingKeyEntries {
			if reflect.DeepEqual(messageKey.PublicKey[:], messagingKeyEntry.MessagingPublicKey[:]) {
				// We will add the messages with the sender messaging public key as the MessageKey
				// so that we have no overlaps in the DB in some weird edge cases.
				mapKey := MakeMessageKey(messageEntry.SenderMessagingPublicKey[:], messageEntry.TstampNanos)
				messagesMap[mapKey] = messageEntry
				break
			}
		}
	}

	// We fetched all UtxoView entries, so now look for messages in the DB.
	dbMessageEntries, err := DBGetLimitedMessageForMessagingKeys(bav.Handle, _messagingKeyEntries, limit)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntries from db: ")
	}
	// Now iterate through all the db message entries and add them to our auxiliary map.
	for _, messageEntry := range dbMessageEntries {
		// Use the sender messaging public key for the MessageKey to make sure they match the UtxoView entries.
		mapKey := MakeMessageKey(messageEntry.SenderMessagingPublicKey[:], messageEntry.TstampNanos)
		if _, exists := messagesMap[mapKey]; !exists {
			messagesMap[mapKey] = messageEntry
		} else {
			// If the message was deleted in the UtxoView, then we remove it from our map struct.
			if messagesMap[mapKey].isDeleted {
				delete(messagesMap, mapKey)
			}
		}
	}

	// We have added all message entries to our auxiliary map so now we transform them into a map.
	for _, messageEntry := range messagesMap {
		_messageEntries = append(_messageEntries, messageEntry)
	}
	return _messageEntries, _messagingKeyEntries, nil
}

func ReadMessageVersion(txn *MsgDeSoTxn) (_version uint8, _err error){
	if txn == nil {
		return 0, fmt.Errorf("ReadMessageVersion: Called with nil MsgDeSoTxn")
	}

	// Check the version of the message by looking at the "V" field in ExtraData.
	var version uint64
	var err error
	if extraV, hasExtraV := txn.ExtraData["V"]; hasExtraV {
		rr := bytes.NewReader(extraV)
		version, err = ReadUvarint(rr)
		if err != nil {
			return 0, errors.Wrapf(RuleErrorPrivateMessageInvalidVersion,
				"ReadMessageVersion: Problem reading message version from ExtraData, error: (%v)", err)
		}
		if version < 0 || version > 3 {
			return 0, errors.Wrapf(RuleErrorPrivateMessageInvalidVersion,
				"ReadMessageVersion: Problem reading message version from ExtraData, expecting version " +
					"between <1, 3> but got (%v)", version)
		}
	}
	return uint8(version), nil
}

func ValidateKeyAndName(messagingPublicKey, keyName []byte) error {
	// This is a helper function that allows us to verify messaging public key and key name.

	// First validate the messagingPublicKey.
	if err := IsByteArrayValidPublicKey(messagingPublicKey); err != nil {
		return errors.Wrapf(err, "ValidateKeyAndName: "+
			"Problem validating sender's messaging key: %v", messagingPublicKey)
	}

	// If we get here, it means that we have a valid messaging public key.
	// Sanity-check messaging key name.
	if len(keyName) < MinMessagingKeyNameCharacters {
		return errors.Wrapf(RuleErrorMessagingKeyNameTooShort, "ValidateKeyAndName: "+
			"Too few characters in key name: min = %v, provided = %v",
			MinMessagingKeyNameCharacters, len(keyName))
	}
	if len(keyName) > MaxMessagingKeyNameCharacters {
		return errors.Wrapf(RuleErrorMessagingKeyNameTooLong, "ValidateKeyAndName: "+
			"Too many characters in key name: max = %v; provided = %v",
			MaxMessagingKeyNameCharacters, len(keyName))
	}
	return nil
}

// ValidateKeyAndNameWithUtxo validates public key and key name, which are used in DeSo V3 Messages protocol.
// The function first checks that the key and name are valid and then fetches an entry from UtxoView or DB
// to check if the key has been previously saved. This is particularly useful for connecting V3 messages.
func (bav *UtxoView) ValidateKeyAndNameWithUtxo(ownerPublicKey, messagingPublicKey, keyName []byte) error {
	// First validate the public key and name with ValidateKeyAndName
	err := ValidateKeyAndName(messagingPublicKey, keyName)
	if err != nil {
		return errors.Wrapf(err, "ValidateKeyAndNameWithUtxo: Failed validating "+
			"messagingPublicKey and keyName")
	}

	// Fetch the messaging key entry from UtxoView.
	messagingKey := NewMessagingKey(NewPublicKey(ownerPublicKey), keyName)
	messagingKeyEntry := bav.GetMessagingKeyToMessagingKeyEntryMapping(messagingKey)
	if messagingKeyEntry == nil || messagingKeyEntry.isDeleted {
		return fmt.Errorf("ValidateKeyAndNameWithUtxo: non-existent messaging key entry "+
			"for ownerPublicKey: %s", PkToString(ownerPublicKey, bav.Params))
	}

	// Compare the UtxoEntry with the provided key for more validation.
	if !reflect.DeepEqual(messagingKeyEntry.MessagingPublicKey[:], messagingPublicKey) {
		return fmt.Errorf("ValidateKeyAndNameWithUtxo: keys don't match for "+
			"ownerPublicKey: %s", PkToString(ownerPublicKey, bav.Params))
	}

	if !EqualKeyName(messagingKeyEntry.MessagingKeyName, NewKeyName(keyName)) {
		return fmt.Errorf("ValidateKeyAndNameWithUtxo: key name don't match for "+
			"ownerPublicKey: %s", PkToString(ownerPublicKey, bav.Params))
	}
	return nil
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

	// You can't send a message to yourself.
	if reflect.DeepEqual(txn.PublicKey, txMeta.RecipientPublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey,
			"_connectPrivateMessage: ")
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

	// Create a MessageEntry, we do this now because we might modify some of the fields
	// based on the version of the message.
	messageEntry := &MessageEntry{
		SenderPublicKey:             NewPublicKey(txn.PublicKey),
		RecipientPublicKey:          NewPublicKey(txMeta.RecipientPublicKey),
		EncryptedText:               txMeta.EncryptedText,
		TstampNanos:                 txMeta.TimestampNanos,
		Version:                     uint8(version),
		SenderMessagingPublicKey:    NewPublicKey(txn.PublicKey),
		SenderMessagingKeyName:      BaseKeyName(),
		RecipientMessagingPublicKey: NewPublicKey(txMeta.RecipientPublicKey),
		RecipientMessagingKeyName:   BaseKeyName(),
	}

	// If message was encrypted using DeSo V3 Messages, we will look for messaging keys in
	// ExtraData. V3 allows users to register messaging keys on-chain, and encrypt messages
	// to these messaging keys, as opposed to encrypting messages to user's main keys.
	if version == 3 {
		// Make sure DeSo V3 messages are live.
		if blockHeight < bav.Params.ForkHeights.DeSoV3MessagesBlockHeight {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageMessagingPartyBeforeBlockHeight,
				"_connectPrivateMessage: messaging party used before block height")
		}
		// Look for messaging keys in transaction ExtraData
		// TODO: Do we want to make the ExtraData keys shorter to save space and transaction cost?
		if txn.ExtraData == nil {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageMissingExtraData,
				"_connectPrivateMessage: ExtraData cannot be nil")
		}
		senderMessagingPublicKey, existsSender := txn.ExtraData[SenderMessagingPublicKey]
		recipientMessagingPublicKey, existsRecipient := txn.ExtraData[RecipientMessagingPublicKey]
		// At least one of these fields must exist if this is a V3 message.
		if !existsSender && !existsRecipient {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageSentWithoutProperMessagingParty,
				"_connectPrivateMessage: at least one messaging party must be present")
		}

		// We will now proceed to add sender's and recipient's messaging keys to the message entry.
		// We make sure that both sender public key and key name is present in transaction's ExtraData.
		senderMessagingKeyName, existsSenderName := txn.ExtraData[SenderMessagingKeyName]
		if existsSender && existsSenderName {
			// Validate the key and the name using this helper function to make sure messaging key has been previously authorized.
			if err = bav.ValidateKeyAndNameWithUtxo(txn.PublicKey, senderMessagingPublicKey, senderMessagingKeyName); err != nil {
				return 0, 0, nil, errors.Wrapf(RuleErrorPrivateMessageFailedToValidateMessagingKey,
					"_connectPrivateMessage: failed to validate public key and key name")
			}
			// If everything went well, update the messaging key information in the message entry.
			messageEntry.SenderMessagingPublicKey = NewPublicKey(senderMessagingPublicKey)
			messageEntry.SenderMessagingKeyName = NewKeyName(senderMessagingKeyName)
		}
		// We do an analogous validation for the recipient's messaging key.
		recipientMessagingKeyName, existsRecipientName := txn.ExtraData[RecipientMessagingKeyName]
		if existsRecipient && existsRecipientName {
			// The below check exists because of an annoying edge-case where group owner wanted to send a message
			// to the group. In this scenario, the sender and recipient public keys would be the same which would
			// make us fail one of the previous checks. To circumvent this, we will enforce that group owners put
			// group's messaging key as the recipient instead of his own public key. This is the "worst" edge-case
			// with the messaging key architecture. Because of this check, we also have to make an exception for
			// when recipient public key can equal messaging public key if it's a base key.
			if !EqualKeyName(NewKeyName(recipientMessagingKeyName), BaseKeyName()) &&
				reflect.DeepEqual(txMeta.RecipientPublicKey, recipientMessagingPublicKey) {
				// We know we entered this edge-case so we verify that the owner previously registered this key.
				if err := bav.ValidateKeyAndNameWithUtxo(txn.PublicKey, recipientMessagingPublicKey, recipientMessagingKeyName); err != nil {
					return 0, 0, nil, errors.Wrapf(RuleErrorPrivateMessageFailedToValidateMessagingKey,
						"_connectPrivateMessage: failed to validate public key and key name, error: (%v)", err)
				}
			} else {
				// Proceed normally in all other cases.
				if err := bav.ValidateKeyAndNameWithUtxo(txMeta.RecipientPublicKey, recipientMessagingPublicKey, recipientMessagingKeyName); err != nil {
					return 0, 0, nil, errors.Wrapf(RuleErrorPrivateMessageFailedToValidateMessagingKey,
						"_connectPrivateMessage: failed to validate public key and key name, error: (%v)", err)
				}
			}
			// If everything worked, update the messaging key information in the message entry.
			messageEntry.RecipientMessagingPublicKey = NewPublicKey(recipientMessagingPublicKey)
			messageEntry.RecipientMessagingKeyName = NewKeyName(recipientMessagingKeyName)
		}
	}

	// Make sure we don't try to send messages between identical public keys.
	if reflect.DeepEqual(messageEntry.SenderPublicKey[:], messageEntry.RecipientPublicKey[:]) ||
		reflect.DeepEqual(messageEntry.SenderMessagingPublicKey[:], messageEntry.RecipientMessagingPublicKey[:]) {
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
		// private messages by the messaging public keys, rather than sender/owner main keys. This is
		// particularly useful in group messages, and allows us to later fetch messages from DB more efficiently.
		senderMessageKey := MakeMessageKey(messageEntry.SenderMessagingPublicKey[:], txMeta.TimestampNanos)
		senderMessage := bav._getMessageEntryForMessageKey(&senderMessageKey)
		if senderMessage != nil && !senderMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &senderMessageKey)
		}
		recipientMessageKey := MakeMessageKey(messageEntry.RecipientMessagingPublicKey[:], txMeta.TimestampNanos)
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
	// <PublicKey, TstampNanos> tuple. We also know that the sender and recipient
	// have different public keys.


	if bav.Postgres != nil {
		//TODO: Fix Postgres
		message := &PGMessage{
			MessageHash:        txn.Hash(),
			SenderPublicKey:    txn.PublicKey,
			RecipientPublicKey: txMeta.RecipientPublicKey,
			EncryptedText:      txMeta.EncryptedText,
			TimestampNanos:     txMeta.TimestampNanos,
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

	// We keep track of sender and recipient messaging public keys. We will update them in V3 messages.
	senderPkBytes := currentTxn.PublicKey
	recipientPkBytes := txMeta.RecipientPublicKey

	// Do some sanity-checks when message is V3.
	if version == 3 {
		if currentTxn.ExtraData == nil {
			return errors.Wrapf(RuleErrorPrivateMessageMissingExtraData,
				"_disconnectPrivateMessage: ExtraData cannot be nil")
		}
		senderMessagingPublicKey, existsSender := currentTxn.ExtraData[SenderMessagingPublicKey]
		recipientMessagingPublicKey, existsRecipient := currentTxn.ExtraData[RecipientMessagingPublicKey]
		// At least one of these fields must exist.
		if !existsSender && !existsRecipient {
			return errors.Wrapf(RuleErrorPrivateMessageSentWithoutProperMessagingParty,
				"_disconnectPrivateMessage: at least one messaging party must be present")
		}
		if existsSender {
			if err := IsByteArrayValidPublicKey(senderMessagingPublicKey); err != nil {
				return errors.Wrapf(RuleErrorPrivateMessageSentWithoutProperMessagingParty,
			"_disconnectPrivateMessage: at least one messaging party must be present")
			}
			senderPkBytes = senderMessagingPublicKey
		}
		if existsRecipient {
			if err := IsByteArrayValidPublicKey(recipientMessagingPublicKey); err != nil {
				return errors.Wrapf(RuleErrorPrivateMessageSentWithoutProperMessagingParty,
				"_disconnectPrivateMessage: at least one messaging party must be present")
			}
			recipientPkBytes = recipientMessagingPublicKey
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
			"MessageEntry was %s but the PublicKey on the txn was %s",
			PkToString(senderMessageEntry.SenderPublicKey[:], bav.Params),
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(senderMessageEntry.RecipientPublicKey[:], txMeta.RecipientPublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Recipient public key on "+
			"MessageEntry was %s but the PublicKey on the TxnMeta was %s",
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

	// Sanity-check V3 data such as sender and recipient messaging public keys.
	// In DeSo V3 Messages, all message entries have these fields.
	if !reflect.DeepEqual(senderMessageEntry.SenderMessagingPublicKey[:], senderPkBytes) {
		return fmt.Errorf("_disconnectPrivateMessage: sender messaging public key in MessageEntry "+
			"did not match the public key in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.SenderMessagingPublicKey[:]),
			hex.EncodeToString(senderPkBytes))
	}

	if !reflect.DeepEqual(senderMessageEntry.RecipientMessagingPublicKey[:], recipientPkBytes) {
		return fmt.Errorf("_disconnectPrivateMessage: sender messaging public key in MessageEntry "+
			"did not match the public key in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.RecipientMessagingPublicKey[:]),
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
	if !reflect.DeepEqual(recipientMessageEntry.Encode(), senderMessageEntry.Encode()) {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for " +
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

func (bav *UtxoView) _connectMessagingKey(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Messaging keys are a part of DeSo V3 Messages.
	// A messaging key is a pair of a public key and a key name. Messaging keys are registered on-chain and are
	// intended to be used as senders/recipients of privateMessage transactions, as opposed to users main keys.
	// Messaging keys solve the problem with messages for holders of derived keys, who previously had no way to
	// properly encrypt/decrypt messages, as they don't have access to user's main private key.
	//
	// A key name is a byte array between 8-32 bytes that labels the messaging public key. Applications have the
	// choice to label users' messaging keys as they desire. For instance, a key name could represent the name of
	// an on-chain group chat. On the db level, key names are always filled to 32 bytes with []byte(0) suffix.
	//
	// We hard-code two messaging keys:
	// 	[]byte{}              : user's main public key. This key is registered for all users natively.
	//	[]byte("default-key") : intended to be registered when authorizing a derived key for the first time.
	//
	// The proposed flow is to register a default key whenever first authorizing a derived key for a user, this
	// way, the derived key can be used for handling messages. DeSo V3 Messages also enable group chats, which
	// we will explain later.

	// Make sure DeSo V3 messages are live.
	if blockHeight < bav.Params.ForkHeights.DeSoV3MessagesBlockHeight {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorMessagingKeyBeforeBlockHeight, "_connectMessagingKey: " +
				"Problem connecting messaging key, too early block height")
	}
	txMeta := txn.TxnMeta.(*MessagingKeyMetadata)

	// If the key name is just a list of 0s, then return because this name is reserved for the base key.
	if EqualKeyName(NewKeyName(txMeta.MessagingKeyName), BaseKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorMessagingKeyNameCannotBeZeros, "_connectMessagingKey: "+
				"Cannot set a zeros-only key name?")
	}

	// Make sure that the messaging public key and the key name have the correct format.
	if err := ValidateKeyAndName(txMeta.MessagingPublicKey, txMeta.MessagingKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: "+
				"Problem parsing public key: %v", txMeta.MessagingPublicKey)
	}

	// Sanity-check that transaction public key is valid.
	if err := IsByteArrayValidPublicKey(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: " +
			"error %v", RuleErrorMessagingOwnerPublicKeyInvalid)
	}

	// Sanity-check that we're not trying to add a messaging public key identical to the main public key.
	if reflect.DeepEqual(txMeta.MessagingPublicKey, txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorMessagingPublicKeyCannotBeOwnerKey,
			"_connectMessagingKey: messaging public key and txn public key can't be the same")
	}

	// We now have a valid messaging public key, key name, and owner public key.
	// The hard-coded default key is only intended to be registered by the owner, so we will require a signature.
	if EqualKeyName(NewKeyName(txMeta.MessagingKeyName), DefaultKeyName()) {
		// Verify the messagingKeySignature. it should be signature( messagingPublicKey || messagingKeyName )
		// We need to make sure the default messaging key was authorized by the master public key.
		// All other keys can be registered by derived keys.
		bytes := append(txMeta.MessagingPublicKey, txMeta.MessagingKeyName...)
		if err := _verifyBytesSignature(txn.PublicKey, bytes, txMeta.KeySignature); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: " +
				"Problem verifying signature bytes, error: %v", RuleErrorMessagingSignatureInvalid)
		}
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: ")
	}

	// We have validated all information. At this point the inputs and outputs have been processed.
	// Now we need to handle the metadata. We will proceed to add the key to UtxoView, and generate UtxoOps.

	// We support "unencrypted" groups, which are a special-case of group chats that are intended for public
	// access. For example, this could be used to make discussion groups, which anyone can discover and join.
	// To do so, we hard-code an owner public key which will index all unencrypted group chats. We choose the
	// secp256k1 base element. Essentially, unencrypted groups are treated as messaging keys that are created
	// by the base element public key. To register an unencrypted group chat, the messaging key transaction
	// should contain the base element as the messaging public key. Below, we check for this and adjust the
	// messaging key and messaging public key appropriately so that we can properly index the DB entry.
	var messagingKey *MessagingKey
	var messagingPublicKey *PublicKey
	if reflect.DeepEqual(txMeta.MessagingPublicKey, GetS256BasePointCompressed()) {
		messagingKey = NewMessagingKey(NewPublicKey(GetS256BasePointCompressed()),  txMeta.MessagingKeyName)
		_, keyPublic := btcec.PrivKeyFromBytes(btcec.S256(), Sha256DoubleHash(txMeta.MessagingKeyName)[:])
		messagingPublicKey = NewPublicKey(keyPublic.SerializeCompressed())
	} else {
		messagingKey = NewMessagingKey(NewPublicKey(txn.PublicKey), txMeta.MessagingKeyName)
		messagingPublicKey = NewPublicKey(txMeta.MessagingPublicKey)
	}
	// First, let's check if this key doesn't already exist in UtxoView or in the DB.
	// It's worth noting that we index messaging keys by the main public key and messaging key name.
	existingEntry := bav.GetMessagingKeyToMessagingKeyEntryMapping(messagingKey)

	// Make sure that the utxoView entry and the transaction entries have the same messaging public keys and encrypted key.
	// The encrypted key is an auxiliary field that can be used to share the private key of the messaging public keys with
	// user's main key when registering a messaging key via a derived key. This field will also be used in group chats, as
	// we will later overload the MessagingKeyEntry struct for storing messaging keys for group participants.
	if existingEntry != nil && !existingEntry.isDeleted {
		if !reflect.DeepEqual(existingEntry.MessagingPublicKey[:], messagingPublicKey[:]) {
			return 0, 0, nil, errors.Wrapf(RuleErrorMessagingPublicKeyCannotBeDifferent,
				"_connectMessagingKey: Messaging public key cannot differ from the existing entry")
		}
	}

	// In DeSo V3 Messages, a messaging key can initialize a group chat with more than two parties. In group chats, all
	// messages are encrypted to the group messaging public key. The group participants are provided with an encrypted
	// private key of the group key so that each of them can read the messages. We refer to these group participants as
	// messaging recipients, and for each recipient we will store a MessagingKeyEntry with the respective encrypted key.
	// The encrypted key must be addressed to a registered messaging key for each recipient, e.g. the base or the default
	// keys. In particular, this design choice allows derived keys to read group messages.
	//
	// A messaging key transaction can either initialize a group messaging key or add more recipients. In the former case,
	// there will be no existing messaging key entry; however, in the latter case there will be an entry present in DB or
	// UtxoView. When adding recipients, we need to make sure that the transaction isn't trying to change data about existing
	// recipients. An important limitation is that the current design doesn't support removing recipients. This would be
	// tricky to impose in consensus, considering that removed users can't *forget* the messaging private key. Removing users
	// can be facilitated in the application-layer, where we can issue a new group key and share it with all valid recipients.

	// We will keep track of all group messaging recipients.
	var messagingRecipients []MessagingRecipient
	// Map all recipients so that it's easier to check for overlapping recipients.
	existingRecipients := make(map[PublicKey]bool)

	// Sanity-check a group messaging key recipients can't contain the messaging public key.
	existingRecipients[*messagingPublicKey] = true

	// If we're adding more group recipients, then we need to make sure there are no overlapping recipients
	// between the transaction's entry, and the existing entry.
	if existingEntry != nil && !existingEntry.isDeleted {
		// We make sure we'll add at least one messaging recipient in the the transaction.
		if len(txMeta.Recipients) == 0 {
			return 0, 0, nil, errors.Wrapf(RuleErrorMessagingKeyDoesntAddRecipients,
				"_connectMessagingKey: Can't update a messaging key without any new recipients")
		}

		// Now iterate through all existing recipients and make sure there are no overlaps.
		for _, recipient := range existingEntry.Recipients {
			if _, exists := existingRecipients[*recipient.RecipientPublicKey]; exists {
				return 0, 0, nil, errors.Wrapf(
					RuleErrorMessagingRecipientAlreadyExists, "_connectMessagingKey: " +
						"Error, recipient already exists (%v)", recipient.RecipientPublicKey[:])
			}

			// Add the recipient to our helper structs.
			existingRecipients[*recipient.RecipientPublicKey] = true
			messagingRecipients = append(messagingRecipients, recipient)
		}
	}

	// Validate all recipients.
	for _, recipient := range txMeta.Recipients {
		// Encrypted public key cannot be empty, and has to have at least as many bytes as a generic private key.
		if len(recipient.EncryptedKey) < btcec.PrivKeyBytesLen {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorMessagingRecipientEncryptedKeyTooShort, "_connectMessagingKey: "+
					"Problem validating recipient encrypted key for recipient (%v)", recipient.RecipientPublicKey[:])
		}

		// Make sure the recipient public key and messaging key name are valid.
		if err := ValidateKeyAndName(recipient.RecipientPublicKey[:], recipient.RecipientMessagingKeyName[:]); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: " +
				"Problem validating public key or messaging key for recipient (%v)", recipient.RecipientPublicKey[:])
		}

		// Now make sure recipient's messaging key has already been added to UtxoView or DB.
		// We encrypt the group messaging key to recipients' messaging keys.
		recipientMessagingKey := NewMessagingKey(recipient.RecipientPublicKey, recipient.RecipientMessagingKeyName[:])
		recipientEntry := bav.GetMessagingKeyToMessagingKeyEntryMapping(recipientMessagingKey)
		// The messaging key has to exist and cannot be deleted.
		if recipientEntry == nil || recipientEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorMessagingRecipientKeyDoesntExist, "_connectMessagingKey: "+
					"Problem verifying messaing key for recipient (%v)", recipient.RecipientPublicKey[:])
		}
		// The recipient can't be already added to the list of existing recipients.
		if _, exists := existingRecipients[*recipient.RecipientPublicKey]; exists {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorMessagingRecipientAlreadyExists, "_connectMessagingKey: " +
					"Error, recipient already exists (%v)", recipient.RecipientPublicKey[:])
		}
		// Add the recipient to our helper structs.
		existingRecipients[*recipient.RecipientPublicKey] = true
		messagingRecipients = append(messagingRecipients, recipient)
	}

	// Create a MessagingKeyEntry so we can add the entry to UtxoView.
	messagingKeyEntry := MessagingKeyEntry{
		MessagingPublicKey: messagingPublicKey,
		MessagingKeyName:   NewKeyName(txMeta.MessagingKeyName),
		Recipients:         messagingRecipients,
		isDeleted:          false,
	}
	// Create an utxoOps entry, we make a copy of the existing entry.
	var prevMessagingKeyEntry *MessagingKeyEntry
	if existingEntry != nil && !existingEntry.isDeleted {
		prevMessagingKeyEntry = &MessagingKeyEntry{}
		prevMessagingKeyEntry.Decode(existingEntry.Encode())
	}
	bav._setMessagingKeyToMessagingKeyEntryMapping(&messagingKey.PublicKey, &messagingKeyEntry)

	// Construct UtxoOperation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeMessagingKey,
		PrevMessagingKeyEntry: prevMessagingKeyEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectMessagingKey(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a MessagingKey operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectMessagingKey: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeMessagingKey {
		return fmt.Errorf("_disconnectMessagingKey: Trying to revert "+
			"OperationTypeMessagingKey but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Now we know the txMeta is MessagingKey
	txMeta := currentTxn.TxnMeta.(*MessagingKeyMetadata)

	// Sanity check that the messaging public key and key name are valid
	err := ValidateKeyAndName(txMeta.MessagingPublicKey, txMeta.MessagingKeyName)
	if err != nil {
		return errors.Wrapf(err, "_disconnectMessagingKey: failed validating the messaging "+
			"public key and key name")
	}

	// Get the messaging key that the transaction metadata points to.
	var messagingKey *MessagingKey
	if reflect.DeepEqual(txMeta.MessagingPublicKey, GetS256BasePointCompressed()) {
		messagingKey = NewMessagingKey(NewPublicKey(GetS256BasePointCompressed()),  txMeta.MessagingKeyName)
	} else {
		messagingKey = NewMessagingKey(NewPublicKey(currentTxn.PublicKey), txMeta.MessagingKeyName)
	}

	messagingKeyEntry := bav.GetMessagingKeyToMessagingKeyEntryMapping(messagingKey)
	if messagingKeyEntry == nil || messagingKeyEntry.isDeleted {
		return fmt.Errorf("_disconnectBasicTransfer: Error, this key was already deleted "+
			"messagingKey: %v", messagingKey)
	}
	prevMessagingKeyEntry := utxoOpsForTxn[operationIndex].PrevMessagingKeyEntry
	// sanity check that the prev entry and current entry match
	if prevMessagingKeyEntry != nil {
		if !reflect.DeepEqual(messagingKeyEntry.MessagingPublicKey[:], prevMessagingKeyEntry.MessagingPublicKey[:]) ||
			!EqualKeyName(messagingKeyEntry.MessagingKeyName, prevMessagingKeyEntry.MessagingKeyName) {

			return fmt.Errorf("_disconnectBasicTransfer: Error, this key was already deleted "+
				"messagingKey: %v", messagingKey)
		}
	}


	// Delete this item from UtxoView to indicate we should remove this entry from DB.
	bav._deleteMessagingKeyToMessagingKeyEntryMapping(&messagingKey.PublicKey, messagingKeyEntry)
	// If the previous entry exists, we should set it in the utxoview
	if prevMessagingKeyEntry != nil {
		bav._setMessagingKeyToMessagingKeyEntryMapping(&messagingKey.PublicKey, prevMessagingKeyEntry)
	}

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}