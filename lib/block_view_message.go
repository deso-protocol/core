package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
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

func (bav *UtxoView) _setMessageEntryMappings(messageEntry *MessageEntry) {
	// This function shouldn't be called with nil.
	if messageEntry == nil {
		glog.Errorf("_setMessageEntryMappings: Called with nil MessageEntry; " +
			"this should never happen.")
		return
	}

	// Add a mapping for the sender and the recipient.
	senderKey := MakeMessageKey(messageEntry.SenderPublicKey, messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[senderKey] = messageEntry

	recipientKey := MakeMessageKey(messageEntry.RecipientPublicKey, messageEntry.TstampNanos)
	bav.MessageKeyToMessageEntry[recipientKey] = messageEntry
}

func (bav *UtxoView) _deleteMessageEntryMappings(messageEntry *MessageEntry) {

	// Create a tombstone entry.
	tombstoneMessageEntry := *messageEntry
	tombstoneMessageEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setMessageEntryMappings(&tombstoneMessageEntry)
}

func (bav *UtxoView) _getPKIDToMessagingKeyMapping(ownerPKID *PKID, messagingKeyName []byte) *MessagingKeyEntry {
	// If an entry exists in the in-memory map, return the value of that mapping.
	mapValue, exists := bav.PKIDToMessagingKey[*ownerPKID]
	if exists {
		return mapValue
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory view mapping got later.
	messagingKeyEntry := DBGetMessagingKeyEntry(bav.Handle, ownerPKID, messagingKeyName)
	if messagingKeyEntry != nil {
		bav._setPKIDToMessagingKeyMapping(messagingKeyEntry)
	}
	return messagingKeyEntry
}

func (bav *UtxoView) _setPKIDToMessagingKeyMapping(messagingKeyEntry *MessagingKeyEntry) {
	// This function shouldn't be called with nil
	if messagingKeyEntry == nil {
		glog.Errorf("_setPKIDToMessagingKeyMapping: Called with nil MessagingKeyEntry; " +
			"this should never happen.")
		return
	}

	bav.PKIDToMessagingKey[*messagingKeyEntry.OwnerPKID] = messagingKeyEntry
}

func (bav *UtxoView) _deletePKIDToMessagingKeyMapping(messagingKeyEntry *MessagingKeyEntry) {

	// Create a tombstone entry.
	tombstoneMessageKeyEntry := *messagingKeyEntry
	tombstoneMessageKeyEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setPKIDToMessagingKeyMapping(&tombstoneMessageKeyEntry)
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
	dbMessageParty := DbGetMessageParty(bav.Handle, key.PublicKey[:], key.TstampNanos)
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

	bav.MessageKeyToMessageParty[MakeMessageKey(party.SenderPublicKey, party.TstampNanos)] = party
	bav.MessageKeyToMessageParty[MakeMessageKey(party.RecipientPublicKey, party.TstampNanos)] = party
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
	_messageEntries []*MessageEntry, _err error) {

	// Start by fetching all the messages we have in the db.
	dbMessageEntries, err := DbGetLimitedMessageEntriesForPublicKey(bav.Handle, publicKey)
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
	if bav.Postgres == nil {
		senderMessageKey := MakeMessageKey(txn.PublicKey, txMeta.TimestampNanos)
		senderMessage := bav._getMessageEntryForMessageKey(&senderMessageKey)
		if senderMessage != nil && !senderMessage.isDeleted {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorPrivateMessageExistsWithSenderPublicKeyTstampTuple,
				"_connectPrivateMessage: Message key: %v", &senderMessageKey)
		}
		recipientMessageKey := MakeMessageKey(txMeta.RecipientPublicKey, txMeta.TimestampNanos)
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

	// Create a MessageEntry
	messageEntry := &MessageEntry{
		SenderPublicKey:    txn.PublicKey,
		RecipientPublicKey: txMeta.RecipientPublicKey,
		EncryptedText:      txMeta.EncryptedText,
		TstampNanos:        txMeta.TimestampNanos,
		Version:            1,
	}

	//Check if message is encrypted with shared secret
	if extraV, hasExtraV := txn.ExtraData["V"]; hasExtraV {
		Version, _ := Uvarint(extraV)
		messageEntry.Version = uint8(Version)
	}

	var senderMessagingPublicKey, recipientMessagingPublicKey, senderMessagingKeyName, recipientMessagingKeyName []byte
	var existsSender, existsRecipient, existsSenderName, existsRecipientName bool
	senderMessagingPublicKey, existsSender = txn.ExtraData[SenderMessagingPublicKey]
	recipientMessagingPublicKey, existsRecipient = txn.ExtraData[RecipientMessagingPublicKey]
	if existsSender || existsRecipient {
		if senderMessagingKeyName, existsSenderName = txn.ExtraData[SenderMessagingKeyName];
				existsSender && existsSenderName {
			if err := ValidateKeyAndName(senderMessagingPublicKey, senderMessagingKeyName); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: "+
					"failed to validate public key and key name")
			}
		}
		if recipientMessagingKeyName, existsRecipientName = txn.ExtraData[RecipientMessagingKeyName];
				existsRecipient || existsRecipientName {
			if err := ValidateKeyAndName(recipientMessagingPublicKey, recipientMessagingKeyName); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectPrivateMessage: "+
					"failed to validate public key and key name")
			}
		}
	}

	if bav.Postgres != nil {
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

	// Verify that the last operation is a PrivateMessage opration
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
	senderMessageKey := MakeMessageKey(currentTxn.PublicKey, txMeta.TimestampNanos)
	messageEntry := bav._getMessageEntryForMessageKey(&senderMessageKey)
	if messageEntry == nil || messageEntry.isDeleted {
		return fmt.Errorf("_disconnectPrivateMessage: MessageEntry for "+
			"SenderMessageKey %v was found to be nil or deleted: %v",
			&senderMessageKey, messageEntry)
	}

	// Verify that the sender and recipient in the entry match the TxnMeta as
	// a sanity check.
	if !reflect.DeepEqual(messageEntry.SenderPublicKey, currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Sender public key on "+
			"MessageEntry was %s but the PublicKey on the txn was %s",
			PkToString(messageEntry.SenderPublicKey, bav.Params),
			PkToString(currentTxn.PublicKey, bav.Params))
	}
	if !reflect.DeepEqual(messageEntry.RecipientPublicKey, txMeta.RecipientPublicKey) {
		return fmt.Errorf("_disconnectPrivateMessage: Recipient public key on "+
			"MessageEntry was %s but the PublicKey on the TxnMeta was %s",
			PkToString(messageEntry.RecipientPublicKey, bav.Params),
			PkToString(txMeta.RecipientPublicKey, bav.Params))
	}
	// Sanity-check that the MessageEntry TstampNanos matches the transaction.
	if messageEntry.TstampNanos != txMeta.TimestampNanos {
		return fmt.Errorf("_disconnectPrivateMessage: TimestampNanos in "+
			"MessageEntry was %d but in transaction it was %d",
			messageEntry.TstampNanos,
			txMeta.TimestampNanos)
	}
	// Sanity-check that the EncryptedText on the MessageEntry matches the transaction
	// just for good measure.
	if !reflect.DeepEqual(messageEntry.EncryptedText, txMeta.EncryptedText) {
		return fmt.Errorf("_disconnectPrivateMessage: EncryptedText in MessageEntry "+
			"did not match EncryptedText in transaction: (%s) != (%s)",
			hex.EncodeToString(messageEntry.EncryptedText),
			hex.EncodeToString(txMeta.EncryptedText))
	}

	// Now that we are confident the MessageEntry lines up with the transaction we're
	// rolling back, use the entry to delete the mappings for this message.
	bav._deleteMessageEntryMappings(messageEntry)

	// Now revert the basic transfer with the remaining operations. Cut off
	// the PrivateMessage operation at the end since we just reverted it.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _connectMessagingKeys(txn *MsgDeSoTxn) (*UtxoOperation, error) {
	if txn.ExtraData == nil {
		return nil, nil
	}

	var messagingPublicKey, messagingKeyName, messagingKeySignature []byte
	var exists bool

	// Check for existence of the MessagingPublicKey in ExtraData
	if messagingPublicKey, exists = txn.ExtraData[MessagingPublicKey]; !exists {
		return nil, nil
	}

	// Check for existence of the MessagingKeyName in ExtraData
	if messagingKeyName, exists = txn.ExtraData[MessagingKeyName]; !exists {
		return nil, errors.Wrapf(
			RuleErrorMessagingKeyNameNotProvided,"_connectMessagingKeys: " +
				"Did you forget to add key name?")
	}

	// Check for existence of the MessagingKeySignature in ExtraData
	if messagingKeySignature, exists = txn.ExtraData[MessagingKeySignature]; !exists {
		return nil, errors.Wrapf(
			RuleErrorMessagingKeySignatureNotProvided,"_connectMessagingKeys: " +
				"Did you forget to add key signature?")
	}

	// If we get here it means that this transaction is trying to update the messaging
	// key. So sanity-check that the public key provided in ExtraData is valid.
	if err := IsByteArrayValidPublicKey(messagingPublicKey, fmt.Sprintf(
		"%v: _connectMessagingKeys: Problem parsing public key: %v",
		RuleErrorMessagingPublicKeyInvalid, messagingPublicKey)); err != nil {
		return nil, err
	}

	// If we get here, it means that we have a valid messaging public key.
	// Sanity check messaging key name
	if len(messagingKeyName) < MinMessagingKeyNameCharacters {
		return nil, errors.Wrapf(
			RuleErrorMessagingKeyNameTooShort, "_connectMessagingKeys: " +
				"Too few characters in key name: min = %v, provided = %v",
				MinMessagingKeyNameCharacters, len(messagingKeyName))
	}
	if len(messagingKeyName) > MaxMessagingKeyNameCharacters {
		return nil, errors.Wrapf(
			RuleErrorMessagingKeyNameTooLong, "_connectMessagingKeys: " +
			"Too many characters in key name: max = %v; provided = %v",
			MaxMessagingKeyNameCharacters, len(messagingKeyName))
	}

	// Now we have a valid messaging public key and key name. So we will proceed
	// to add keys to UtxoView, and generate UtxoOps in case we will revert.
	// Sanity-check that transaction public key is valid.
	if err := IsByteArrayValidPublicKey(txn.PublicKey, fmt.Sprintf("%v",
		RuleErrorMessagingOwnerPublicKeyInvalid)); err != nil {
		return nil, err
	}

	// We now have a valid messaging public key, key name, and owner public key.
	// Verify the messagingKeySignature to check the signature( messagingPublicKey || messagingKeyName )
	bytes := append(messagingPublicKey, messagingKeyName...)
	if err := _verifyBytesSignature(txn.PublicKey, bytes, messagingKeySignature); err != nil {
		return nil, errors.Wrapf(err, "_connectMessagingKeys: " +
		"Problem verifying signature bytes")
	}

	// Create a MessagingKeyEntry struct
	// Get the PKIDs for the public keys associated with the messaging key owner.
	ownerPKIDEntry := bav.GetPKIDForPublicKey(txn.PublicKey)
	if ownerPKIDEntry == nil || ownerPKIDEntry.isDeleted {
		return nil, fmt.Errorf("_connectMessagingKeys: ownerPKID was nil or deleted;" +
			" this should never happen")
	}

	if entry := bav._getPKIDToMessagingKeyMapping(ownerPKIDEntry.PKID, messagingKeyName); entry != nil {
		return nil, fmt.Errorf("_connectMessagingKeys: Error, this key already exists; " +
			"ownerPKID: %v, messagingPublicKey: %v, messagingKeyName: %v",
			ownerPKIDEntry.PKID, entry.MessagingPublicKey, messagingKeyName)
	}

	// Add the messaging key entry to UtxoView
	messagingKeyEntry := MessagingKeyEntry{
		OwnerPKID:          ownerPKIDEntry.PKID,
		MessagingPublicKey: messagingPublicKey,
		MessagingKeyName:   messagingKeyName,
		isDeleted:          false,
	}
	bav._setPKIDToMessagingKeyMapping(&messagingKeyEntry)

	// Construct UtxoOperation.
	messagingKeyOps := UtxoOperation{
		Type:                 OperationTypeMessagingKey,
		PrevMessagingKeyName: messagingKeyName,
	}

	return &messagingKeyOps, nil
}