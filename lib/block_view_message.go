package lib

import (
	"bytes"
"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

func (bav *UtxoView) _getMessageEntryForMessageKey(messageKey *MessageKey) *MessageEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.MessageKeyToMessageEntry[*messageKey]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	dbMessageEntry := DbGetMessageEntry(bav.Handle, messageKey.PublicKey[:], messageKey.TstampNanos)
	if dbMessageEntry != nil {
		bav._setMessageEntryMappings(dbMessageEntry)
	}
	return dbMessageEntry
}

// This function has to be called twice for both sender and recipient!
func (bav *UtxoView) _setMessageEntryMappings(messageEntry *MessageEntry) {
	// This function shouldn't be called with nil.
	if messageEntry == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil MessageEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the sender and the recipient.

	senderKey := MakeMessageKey(messageEntry.SenderMessagingPublicKey[:], messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[senderKey] = &(*messageEntry)

	recipientKey := MakeMessageKey(messageEntry.RecipientMessagingPublicKey[:], messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[recipientKey] = &(*messageEntry)
	//recipientKey := MakeMessageKey(messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
	//bav.MessageKeyToMessageEntry[recipientKey] = messageEntry
}

// This function has to be called twice for both sender and recipient!
func (bav *UtxoView) _deleteMessageEntryMappings(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessageEntryMappings(&tombstoneMessageEntry)
}

func (bav *UtxoView) GetMessagingKeyToMessagingKeyEntryMapping(messagingKey *MessagingKey) *MessagingKeyEntry {
	if EqualKeyName(&messagingKey.KeyName, BaseKeyName()) {
		return &MessagingKeyEntry{
			publicKey: NewPublicKey(messagingKey.PublicKey[:]),
			MessagingPublicKey: NewPublicKey(messagingKey.PublicKey[:]),
			MessagingKeyName: BaseKeyName(),
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
		bav._setMessagingKeyToMessagingKeyEntryMapping(messagingKeyEntry)
	}
	return messagingKeyEntry
}

func (bav *UtxoView) _setMessagingKeyToMessagingKeyEntryMapping(messagingKeyEntry *MessagingKeyEntry) {
	// This function shouldn't be called with nil
	if messagingKeyEntry == nil {
		glog.Errorf("_setMessagingKeyToMessagingKeyEntryMapping: Called with nil MessagingKeyEntry; " +
			"this should never happen.")
		return
	}

	// Create a key for the UtxoView mapping. We always put user's main public key as part of the map key.
	messagingKey := MessagingKey{
		PublicKey: *messagingKeyEntry.publicKey,
		KeyName:   *messagingKeyEntry.MessagingKeyName,
	}
	bav.MessagingKeyToMessagingKeyEntry[messagingKey] = messagingKeyEntry
}

func (bav *UtxoView) _deleteMessagingKeyToMessagingKeyEntryMapping(messagingKeyEntry *MessagingKeyEntry) {

	// Create a tombstone entry.
	tombstoneMessageKeyEntry := *messagingKeyEntry
	tombstoneMessageKeyEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessagingKeyToMessagingKeyEntryMapping(&tombstoneMessageKeyEntry)
}

func (bav *UtxoView) _getMessageKeyToMessageParty(key *MessageKey) *MessageParty {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, existsMapValue := bav.MessageKeyToMessageParty[*key]
	if existsMapValue {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	dbMessageParty := DbGetMessageParty(bav.Handle, NewPublicKey(key.PublicKey[:]), key.TstampNanos)
	if dbMessageParty != nil {
		bav._setMessageKeyToMessageParty(dbMessageParty)
	}
	return dbMessageParty
}

func (bav *UtxoView) _setMessageKeyToMessageParty(party *MessageParty) {
	// This function shouldn't be called with nil
	if party == nil {
		glog.Errorf("_setMessageKeyToMessageParty: Called with nil party; " +
			"this should never happen.")
		return
	}

	// We set the mapping both for the sender and the recipient.
	bav.MessageKeyToMessageParty[MakeMessageKey(party.SenderMessagingPublicKey.ToBytes(), party.TstampNanos)] = party
	bav.MessageKeyToMessageParty[MakeMessageKey(party.RecipientMessagingPublicKey.ToBytes(), party.TstampNanos)] = party
}

func (bav *UtxoView) _deleteMessagePartyMappings(party *MessageParty) {

	// Create a tombstone entry.
	tombstoneMessageParty := *party
	tombstoneMessageParty.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessageKeyToMessageParty(&tombstoneMessageParty)
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

// TODO: Update for Postgres
func (bav *UtxoView) GetMessagesForUser(publicKey []byte) (
	_messageEntries []*MessageEntry, _err error) {

	//TODO: this won't work.
	// Start by fetching all the messages we have in the db.
	dbMessageEntries, err := DbGetMessageEntriesForPublicKey(bav.Handle, publicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntrys from db: ")
	}

	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	for _, dbMessageEntry := range dbMessageEntries {
		messageKey := MakeMessageKey(publicKey, dbMessageEntry.TstampNanos)
		bav._getMessageEntryForMessageKey(&messageKey)
	}

	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning. Skip entries that don't match
	// our public key or that are deleted. Note that only considering mappings
	// where our public key is part of the key should ensure there are no
	// duplicates in the resulting list.
	messageEntriesToReturn := []*MessageEntry{}
	for viewMessageKey, viewMessageEntry := range bav.MessageKeyToMessageEntry {
		if viewMessageEntry.isDeleted {
			continue
		}
		messageKey := MakeMessageKey(publicKey, viewMessageEntry.TstampNanos)
		if viewMessageKey != messageKey {
			continue
		}

		// At this point we are confident the map key is equal to the message
		// key containing the passed-in public key so add it to the mapping.
		messageEntriesToReturn = append(messageEntriesToReturn, viewMessageEntry)
	}

	return messageEntriesToReturn, nil
}

// TODO: Update for Postgres
func (bav *UtxoView) GetLimitedMessagesForUser(publicKey []byte) (
	_messageEntries []*MessageEntry, _messageParties []*MessageParty, _err error) {

	// Start by fetching all the messages we have in the db.
	dbMessageEntries, dbMessageParties, dbMessageKeys, err := DbGetLimitedMessageAndPartyEntriesForPublicKey(bav.Handle, publicKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetMessagesForUser: Problem fetching MessageEntrys from db: ")
	}

	messageKeysMap := make(map[PublicKey]*MessagingKeyEntry)
	err = bav.Handle.View(func(txn *badger.Txn) error {
		userKeys, err := DbGetAllUserMessagingKeys(txn, publicKey)
		if err != nil {
			return err
		}
		for _, key := range userKeys {
			messageKeysMap[*key.MessagingPublicKey] = key
		}
		return nil
	})
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetLimitedMessagesForUser: problem getting user messaging keys")
	}

	// Welp this seems very, very inefficient.
	// Iterate through the entries found in the db and force the view to load them.
	// This fills in any gaps in the view so that, after this, the view should contain
	// the union of what it had before plus what was in the db.
	//for _, dbMessageEntry := range dbMessageEntries {
	//	messageKey := MakeMessageKey(publicKey, dbMessageEntry.TstampNanos)
	//	bav._getMessageEntryForMessageKey(&messageKey)
	//}
	// Now that the view mappings are a complete picture, iterate through them
	// and set them on the map we're returning. Skip entries that don't match
	// our public key or that are deleted. Note that only considering mappings
	// where our public key is part of the key should ensure there are no
	// duplicates in the resulting list.

	// We will add the DB entries to a map so we can easily compare them with the UtxoView entries.
	// We have to expand our DB entries list with the UtxoView entries but also trim the deleted entries.
	messagesMap := make(map[MessageKey]*MessageEntry)
	partiesMap := make(map[MessageKey]*MessageParty)
	keyMap := make(map[MessageKey]*MessagingKeyEntry)
	for ii, entry := range dbMessageEntries {
		if entry == nil {
			continue
		}
		messagesMap[MakeMessageKey(dbMessageKeys[ii].MessagingPublicKey[:], entry.TstampNanos)] = entry
		partiesMap[MakeMessageKey(dbMessageKeys[ii].MessagingPublicKey[:], entry.TstampNanos)] = dbMessageParties[ii]
		keyMap[MakeMessageKey(dbMessageKeys[ii].MessagingPublicKey[:], entry.TstampNanos)] = dbMessageKeys[ii]
	}

	// We will look through entries in UtxoView to make sure we didn't record deleted messages,
	// and so that we get most recent user messages.
	for viewMessageKey, viewMessageEntry := range bav.MessageKeyToMessageEntry {
		// First make sure we're only considering entries that are relevant to provided public key.
		if _, exists := messageKeysMap[*NewPublicKey(viewMessageKey.PublicKey[:])]; !exists {
			continue
		}
		messageKey := MakeMessageKey(viewMessageKey.PublicKey[:], viewMessageEntry.TstampNanos)

		// If the entry is deleted, then we have to make sure we remove it from messagesMap.
		if viewMessageEntry.isDeleted {
			delete(messagesMap, messageKey)
			delete(partiesMap, messageKey)
			delete(keyMap, messageKey)
			continue
		}

		// At this point we are confident the map key is equal to the message key containing
		// the passed-in public key so add it to the mapping.
		messagesMap[messageKey] = viewMessageEntry
		// Now we lookup corresponding party in UtxoView and if it exists, we add it to our partiesMap.
		// We don't need to check if the entry is deleted or not, because we know messages and parties
		// can't have mismatching isDeleted.
		if party, exists := bav.MessageKeyToMessageParty[messageKey]; exists {
			partiesMap[messageKey] = party
		}
	}

	// Now we will construct the message entry and party lists, which we will then return.
	_messageEntries = []*MessageEntry{}
	_messageParties = []*MessageParty{}
	for _, entry := range messagesMap {
		_messageEntries = append(_messageEntries, entry)
		if party, exists := partiesMap[MakeMessageKey(publicKey, entry.TstampNanos)]; exists {
			_messageParties = append(_messageParties, party)
		} else {
			_messageParties = append(_messageParties, nil)
		}
	}

	return _messageEntries, _messageParties, nil
}

func ValidateKeyAndName(messagingPublicKey, keyName []byte) error {
	if len(messagingPublicKey) > 0 {
		// First validate the messagingPublicKey.
		if err := IsByteArrayValidPublicKey(messagingPublicKey); err != nil {
			return errors.Wrapf(err, "ValidateKeyAndNameWithUtxo: "+
				"Problem validating sender's messaging key: %v", messagingPublicKey)
		}

		// If we get here, it means that we have a valid messaging public key.
		// Sanity-check messaging key name.
		if len(keyName) < MinMessagingKeyNameCharacters {
			return errors.Wrapf(RuleErrorMessagingKeyNameTooShort, "ValidateKeyAndNameWithUtxo: "+
				"Too few characters in key name: min = %v, provided = %v",
				MinMessagingKeyNameCharacters, len(keyName))
		}
		if len(keyName) > MaxMessagingKeyNameCharacters {
			return errors.Wrapf(RuleErrorMessagingKeyNameTooLong, "ValidateKeyAndNameWithUtxo: "+
				"Too many characters in key name: max = %v; provided = %v",
				MaxMessagingKeyNameCharacters, len(keyName))
		}
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
	if len(txMeta.RecipientPublicKey) != btcec.PubKeyBytesLenCompressed {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageRecipientPubKeyLen, "_connectPrivateMessage: "+
				"RecipientPubKeyLen = %d; Expected length = %d",
			len(txMeta.RecipientPublicKey), btcec.PubKeyBytesLenCompressed)
	}
	_, err := btcec.ParsePubKey(txMeta.RecipientPublicKey, btcec.S256())
	if err != nil {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageParsePubKeyError, "_connectPrivateMessage: Parse error: %v", err)
	}

	// You can't send a message to yourself.
	if reflect.DeepEqual(txn.PublicKey, txMeta.RecipientPublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey,
			"_connectPrivateMessage: Parse error: %v", err)
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

	// If a message already exists and does not have isDeleted=true then return
	// an error. In general, messages must have unique (pubkey, tstamp) tuples.
	//
	// Postgres does not enforce these rule errors

	//Check if message is encrypted with shared secret
	var version uint64
	if extraV, hasExtraV := txn.ExtraData["V"]; hasExtraV {
		rr := bytes.NewReader(extraV)
		version, err = ReadUvarint(rr)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: Problem reading " +
				"version from ExtraData")
		}
		if version > 3 {
			return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: Problem reading " +
				"version from ExtraData")
		}
	}

	// Create a MessageEntry
	messageEntry := &MessageEntry{
		SenderPublicKey:    NewPublicKey(txn.PublicKey),
		RecipientPublicKey: NewPublicKey(txMeta.RecipientPublicKey),
		EncryptedText:      txMeta.EncryptedText,
		TstampNanos:        txMeta.TimestampNanos,
		Version:            uint8(version),
	}

	// If message was encrypted using DeSo V3 Messages, we will look for messaging keys in
	// ExtraData. V3 allows users to register messaging keys on-chain, and encrypt messages
	// to these messaging keys, as opposed to always encrypting to user main keys.
	var senderPkBytes, recipientPkBytes []byte
	if version == 3 {
		// Make sure DeSo V3 messages are live.
		if blockHeight < DeSoV3MessagesBlockHeight {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageMessagingPartyBeforeBlockHeight,
				"_connectPrivateMessage: messaging party used before block height")
		}
		// Look for messaging keys in transaction ExtraData
		// TODO: Do we want to make the ExtraData keys shorter to save space and transaction cost?
		if txn.ExtraData == nil {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageMessagingPartyBeforeBlockHeight,
				"_connectPrivateMessage: ExtraData cannot be nil")
		}
		senderMessagingPublicKey, existsSender := txn.ExtraData[SenderMessagingPublicKey]
		recipientMessagingPublicKey, existsRecipient := txn.ExtraData[RecipientMessagingPublicKey]
		// At least one of these fields must exist.
		if !existsSender && !existsRecipient {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageSentWithoutMessagingParty,
				"_connectPrivateMessage: at least one messaging party must be present")
		}

		// We will now proceed to add sender's or recipient's messaging keys to the messageParty.
		// We make sure that both sender public key and key name is present in transaction's ExtraData.
		senderMessagingKeyName, existsSenderName := txn.ExtraData[SenderMessagingKeyName]
		// In a slightly nasty way, we check if a non-empty sender-related messaging key is present in ExtraData.
		if existsSender && existsSenderName {
			// We validate the key and the name using this helper function to make sure messaging key has been previously authorized.
			if err = bav.ValidateKeyAndNameWithUtxo(txn.PublicKey, senderMessagingPublicKey, senderMessagingKeyName); err != nil {
				return 0, 0, nil, errors.Wrapf(err,
					"_connectPrivateMessage: failed to validate public key and key name")
			}
			// If everything went well, update the messaging key information in the messageParty.
			messageEntry.SenderMessagingPublicKey = NewPublicKey(senderMessagingPublicKey)
			messageEntry.SenderMessagingKeyName = NewKeyName(senderMessagingKeyName)
		} else {
			// If the key doesn't exist, we will set the messaging key as the sender's main key, along with a byte identifier of 0s.
			messageEntry.SenderMessagingPublicKey = NewPublicKey(txn.PublicKey)
			messageEntry.SenderMessagingKeyName = BaseKeyName()
		}
		// We do an analogous validation for the recipient's messaging key.
		recipientMessagingKeyName, existsRecipientName := txn.ExtraData[RecipientMessagingKeyName]
		if existsRecipient && existsRecipientName {
			if reflect.DeepEqual(txMeta.RecipientPublicKey, recipientMessagingPublicKey) {
				if err := bav.ValidateKeyAndNameWithUtxo(txn.PublicKey, recipientMessagingPublicKey, recipientMessagingKeyName); err != nil {
					return 0, 0, nil, errors.Wrapf(err,
						"_connectPrivateMessage: failed to validate public key and key name")
				}
			} else {
				if err := bav.ValidateKeyAndNameWithUtxo(txMeta.RecipientPublicKey, recipientMessagingPublicKey, recipientMessagingKeyName); err != nil {
					return 0, 0, nil, errors.Wrapf(err,
						"_connectPrivateMessage: failed to validate public key and key name")
				}
			}

			messageEntry.RecipientMessagingPublicKey = NewPublicKey(recipientMessagingPublicKey)
			messageEntry.RecipientMessagingKeyName = NewKeyName(recipientMessagingKeyName)
		} else {
			messageEntry.RecipientMessagingPublicKey = NewPublicKey(txMeta.RecipientPublicKey)
			messageEntry.RecipientMessagingKeyName = BaseKeyName()
		}

		senderPkBytes = messageEntry.SenderMessagingPublicKey[:]
		recipientPkBytes = messageEntry.RecipientMessagingPublicKey[:]
		if reflect.DeepEqual(senderPkBytes, recipientPkBytes) {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageSenderPublicKeyEqualsRecipientPublicKey,
				"_connectPrivateMessage: Parse error: %v", err)
		}
	} else {
		messageEntry.SenderMessagingPublicKey = NewPublicKey(txn.PublicKey)
		messageEntry.SenderMessagingKeyName = BaseKeyName()
		messageEntry.RecipientMessagingPublicKey = NewPublicKey(txMeta.RecipientPublicKey)
		messageEntry.RecipientMessagingKeyName = BaseKeyName()

		senderPkBytes = messageEntry.SenderPublicKey[:]
		recipientPkBytes = messageEntry.RecipientPublicKey[:]
	}

	if bav.Postgres == nil {
		senderMessageKey := MakeMessageKey(senderPkBytes, txMeta.TimestampNanos)
		senderMessage := bav._getMessageEntryForMessageKey(&senderMessageKey)
		if senderMessage != nil && !senderMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &senderMessageKey)
		}
		recipientMessageKey := MakeMessageKey(recipientPkBytes, txMeta.TimestampNanos)
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

	// Get the MessageEntry for the sender in the transaction. If we don't find
	// it or if it has isDeleted=true that's an error.
	var version uint64
	var err error
	if extraV, hasExtraV := currentTxn.ExtraData["V"]; hasExtraV {
		rr := bytes.NewReader(extraV)
		version, err = ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "_connectPrivateMessage: Problem reading " +
				"version from ExtraData")
		}
		if version > 3 {
			return errors.Wrapf(err, "_connectPrivateMessage: Problem reading " +
				"version from ExtraData")
		}
	}

	var senderPkBytes, recipientPkBytes []byte
	if version == 3 {
		if currentTxn.ExtraData == nil {
			return errors.Wrapf(RuleErrorPrivateMessageMessagingPartyBeforeBlockHeight,
				"_connectPrivateMessage: ExtraData cannot be nil")
		}
		senderMessagingPublicKey, existsSender := currentTxn.ExtraData[SenderMessagingPublicKey]
		recipientMessagingPublicKey, existsRecipient := currentTxn.ExtraData[RecipientMessagingPublicKey]
		// At least one of these fields must exist.
		if !existsSender && !existsRecipient {
			return errors.Wrapf(RuleErrorPrivateMessageSentWithoutMessagingParty,
				"_connectPrivateMessage: at least one messaging party must be present")
		}
		if existsSender {
			if err = IsByteArrayValidPublicKey(senderMessagingPublicKey); err != nil {
				return errors.Wrapf(RuleErrorPrivateMessageSentWithoutMessagingParty,
			"_connectPrivateMessage: at least one messaging party must be present")
			}
			senderPkBytes = senderMessagingPublicKey
		} else {
			senderPkBytes = currentTxn.PublicKey
		}
		if existsRecipient {
			if err = IsByteArrayValidPublicKey(recipientMessagingPublicKey); err == nil {
				return errors.Wrapf(RuleErrorPrivateMessageSentWithoutMessagingParty,
				"_connectPrivateMessage: at least one messaging party must be present")
			}
			recipientPkBytes = recipientMessagingPublicKey
		} else {
			recipientPkBytes = txMeta.RecipientPublicKey
		}
	} else {
		senderPkBytes = currentTxn.PublicKey
		recipientPkBytes = txMeta.RecipientPublicKey
	}

	senderMessageKey := MakeMessageKey(senderPkBytes, txMeta.TimestampNanos)
	senderMessageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if senderMessageEntry == nil || senderMessageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&senderMessageKey, senderMessageEntry)
	}

	// Verify that the sender and recipient in the entry match the TxnMeta as
	// a sanity check.
	if !reflect.DeepEqual(senderMessageEntry.SenderPublicKey[:], currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Sender public key on "+
			"MessageEntry was %s but the PublicKey on the txn was %s",
			PkToString(senderMessageEntry.SenderPublicKey[:], bav.Params),
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(senderMessageEntry.RecipientPublicKey, txMeta.RecipientPublicKey) {
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

	if !reflect.DeepEqual(senderMessageEntry.SenderMessagingPublicKey[:], senderPkBytes) {
		return fmt.Errorf("_disconnectPrivateMessage: EncryptedText in MessageEntry "+
			"did not match EncryptedText in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.EncryptedText),
			hex.EncodeToString(txMeta.EncryptedText))
	}

	if !reflect.DeepEqual(senderMessageEntry.RecipientMessagingPublicKey[:], recipientPkBytes) {
		return fmt.Errorf("_disconnectPrivateMessage: EncryptedText in MessageEntry "+
			"did not match EncryptedText in transaction: (%s) != (%s)",
			hex.EncodeToString(senderMessageEntry.EncryptedText),
			hex.EncodeToString(txMeta.EncryptedText))
	}

	// We passed all sanity checks now fetch the recipient entry
	recipientMessageKey := MakeMessageKey(recipientPkBytes, txMeta.TimestampNanos)
	recipientMessageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if recipientMessageEntry == nil || recipientMessageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&recipientMessageKey, recipientMessageEntry)
	}

	// Make sure the sender and recipient entries are identical
	if !reflect.DeepEqual(recipientMessageEntry.Encode(), senderMessageEntry.Encode()) {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&recipientMessageKey, recipientMessageEntry)
	}

	// If we got here then we passed all sanity checks and we're ready to delete the private message entries.

	// Now that we are confident the MessageEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this message.
	bav._deleteMessageEntryMappings(senderMessageEntry)
	bav._deleteMessageEntryMappings(recipientMessageEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the PrivateMessage operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _connectMessagingKey(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Make sure DeSo V3 messages are live.
	if blockHeight < DeSoV3MessagesBlockHeight {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorMessagingKeyBeforeBlockHeight, "_connectMessagingKey: " +
				"Problem connecting messaging key, too early block height")
	}
	txMeta := txn.TxnMeta.(*MessagingKeyMetadata)

	// If the key name is just a list of 0s, then return because this name is reserved for the main key.
	if EqualKeyName(NewKeyName(txMeta.MessagingKeyName), BaseKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorMessagingKeyNameCannotBeZeros, "_connectMessagingKey: "+
				"Cannot set a zeros-only key name?")
	}

	// If we get here it means that this transaction is trying to update the messaging
	// key. So sanity-check that the public key and key name provided in ExtraData are valid.
	if err := ValidateKeyAndName(txMeta.MessagingPublicKey, txMeta.MessagingKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorMessagingPublicKeyInvalid, "_connectMessagingKey: "+
				"Problem parsing public key: %v", txMeta.MessagingPublicKey)
	}

	// Sanity-check that transaction public key is valid.
	if err := IsByteArrayValidPublicKey(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: " +
			"error %v", RuleErrorMessagingOwnerPublicKeyInvalid)
	}

	// We now have a valid messaging public key, key name, and owner public key.
	// Verify the messagingKeySignature. it should be signature( messagingPublicKey || messagingKeyName )
	// We need to make sure the default messaging key was authorized by the master public key
	// all other keys can be managed by derived keys.
	if EqualKeyName(NewKeyName(txMeta.MessagingKeyName), DefaultKeyName()) {
		bytes := append(txMeta.MessagingPublicKey, txMeta.MessagingKeyName...)
		if err := _verifyBytesSignature(txn.PublicKey, bytes, txMeta.KeySignature); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectMessagingKey: " +
				"Problem verifying signature bytes")
		}
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: ")
	}

	// We have validated all information. At this point the inputs and outputs have been processed.
	// Now we need to handle the metadata. We will proceed to add the key to UtxoView, and generate UtxoOps.

	// First, let's check that this key doesn't already exist in UtxoView or in the DB.
	// If a key already exists in the DB then it's non-nil and it wasn't deleted.
	messagingKey := NewMessagingKey(NewPublicKey(txn.PublicKey), txMeta.MessagingKeyName)
	entry := bav.GetMessagingKeyToMessagingKeyEntryMapping(messagingKey)

	// Make sure that the utxoView entry and the transaction entries have the same messaging public keys.
	if entry != nil && !entry.isDeleted {
		if !reflect.DeepEqual(entry.MessagingPublicKey[:], txMeta.MessagingPublicKey) {
			return 0, 0, nil, fmt.Errorf("_connectMessagingKey: " +
			"Problem verifying signature bytes")
		}
	}

	// A messaging key transaction can initialize or manage a group chat, in the latter case we can add more
	// recipients to the group thread. We need to make sure that the transaction isn't trying to modify existing recipients.
	// We only allow adding message recipients, since they already have access to the messaging private key. For
	// removing recipients, a new chat has to be created.
	var messageRecipients []MessageRecipient
	existingRecipients := make(map[PublicKey]bool)
	// A group messaging key recipients can't contain the main user's public key, nor the messaging public key.
	// For adding the encrypted messaging key the messaging key entry, one needs to put the encrytped bytes in EncryptedKey field
	existingRecipients[*NewPublicKey(txn.PublicKey)] = true
	existingRecipients[*NewPublicKey(txMeta.MessagingPublicKey)] = true
	// If entry exists in UtxoView, we will only process this transaction if it adds new recipients
	for _, recipient := range txMeta.Recipients {
		// Encrypted public key cannot be empty
		if len(recipient.EncryptedPublicKey) == 0 {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorMessagingPublicKeyInvalid, "_connectMessagingKey: "+
					"Problem parsing public key: %v", txMeta.MessagingPublicKey)
		}
		// Make sure the recipient public key and messaging key name are valid.
		// The message recipients have an encrypted main messaging key for each of them, encrypted to their messaging keys.
		if err := ValidateKeyAndName(recipient.RecipientPublicKey[:], recipient.RecipientMessagingKeyName[:]); err != nil {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorMessagingPublicKeyInvalid, "_connectMessagingKey: "+
					"Problem parsing public key: %v", txMeta.MessagingPublicKey)
		}
		// Now make sure the messaging key has already been added to the UtxoView.
		recipientMessagingKey := NewMessagingKey(recipient.RecipientPublicKey, recipient.RecipientMessagingKeyName[:])
		recipientEntry := bav.GetMessagingKeyToMessagingKeyEntryMapping(recipientMessagingKey)
		// The messaging key has to exist and cannot be deleted.
		if recipientEntry == nil || recipientEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorMessagingPublicKeyInvalid, "_connectMessagingKey: "+
					"Problem parsing public key: %v", txMeta.MessagingPublicKey)
		}
		// The recipient can't be already added to the list of existing recipients.
		if _, exists := existingRecipients[*recipient.RecipientPublicKey]; exists {
			return 0, 0, nil, fmt.Errorf("_connectMessagingKey: Error, this key already exists; "+
				"messagingKey %v, messagingPublicKey %v", messagingKey, txMeta.MessagingPublicKey)
		}
		// Add the recipient to our helper structs
		existingRecipients[*recipient.RecipientPublicKey] = true
		messageRecipients = append(messageRecipients, recipient)
	}
	// If we're adding more group recipients, then the messaging key entry was already in utxoView
	// we now make sure there are no overlapping recipients between the entry from the transaction, and the
	// existing entry.
	if entry != nil && !entry.isDeleted {
		if len(messageRecipients) == 0 && reflect.DeepEqual(txMeta.EncryptedKey, entry.EncryptedKey) {
			return 0, 0, nil, fmt.Errorf("_connectMessagingKey: Can't update a messaging key without " +
				"any new recipients, nor without updating the encrypted key")
		}
		for _, recipient := range entry.Recipients {
			if _, exists := existingRecipients[*recipient.RecipientPublicKey]; exists {
				return 0, 0, nil, fmt.Errorf("_connectMessagingKey: Error, this key already exists; "+
					"messagingKey %v, messagingPublicKey %v", messagingKey, txMeta.MessagingPublicKey)
			}
			existingRecipients[*recipient.RecipientPublicKey] = true
			messageRecipients = append(messageRecipients, recipient)
		}
	}

	// Create a MessagingKeyEntry and add the entry to UtxoView.
	// We add a new messaging key entry with all the updated information such as the
	messagingKeyEntry := MessagingKeyEntry{
		publicKey:          NewPublicKey(txn.PublicKey),
		MessagingPublicKey: NewPublicKey(txMeta.MessagingPublicKey),
		MessagingKeyName:   NewKeyName(txMeta.MessagingKeyName),
		Recipients:         messageRecipients,
		EncryptedKey:       txMeta.EncryptedKey,
		isDeleted:          false,
	}
	// Create an utxoOps entry, we make a copy of the existing entry.
	var prevMessagingKeyEntry *MessagingKeyEntry
	prevMessagingKeyEntry = nil
	if entry != nil {
		prevMessagingKeyEntry = &(*entry)
	}
	bav._setMessagingKeyToMessagingKeyEntryMapping(&messagingKeyEntry)

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

	// Get the messaging key that the messaging key name from ExtraData points to.
	messagingKey := NewMessagingKey(NewPublicKey(currentTxn.PublicKey), txMeta.MessagingKeyName)
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
	bav._deleteMessagingKeyToMessagingKeyEntryMapping(messagingKeyEntry)
	// If the previous entry exists, we should set it in the utxoview
	if prevMessagingKeyEntry != nil {
		bav._setMessagingKeyToMessagingKeyEntryMapping(prevMessagingKeyEntry)
	}

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}