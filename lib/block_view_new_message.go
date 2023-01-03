package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"sort"
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

func (bav *UtxoView) GetPaginatedMessageEntriesForGroupChatThread(groupChatThread AccessGroupId, startingTimestamp uint64,
	maxMessagesToFetch uint64) (_messageEntries []*NewMessageEntry, _err error) {

	return bav._getPaginatedMessageEntriesForGroupChatThreadRecursionSafe(groupChatThread, startingTimestamp,
		maxMessagesToFetch, MaxGroupChatMessageRecursionDepth)
}

func (bav *UtxoView) _getPaginatedMessageEntriesForGroupChatThreadRecursionSafe(groupChatThread AccessGroupId,
	startingTimestamp uint64, maxMessagesToFetch uint64, maxDepth uint32) (_messageEntries []*NewMessageEntry, _err error) {

	if maxMessagesToFetch == 0 {
		return nil, nil
	}
	// This function can make recursive calls to itself. We use a depth counter to prevent infinite recursion
	// (which shouldn't happen anyway, but better safe than sorry, right?).
	if maxDepth == 0 {
		return nil, errors.Wrapf(RuleErrorNewMessageGetGroupMessagesRecursionLimit,
			"_getPaginatedMessageEntriesForGroupChatThreadRecursionSafe: maxDepth == 0")
	}

	// Fetch the message entries from db.
	dbAdapter := bav.GetDbAdapter()
	dbMessageEntries, err := dbAdapter.GetPaginatedMessageEntriesForGroupChatThread(groupChatThread, startingTimestamp, maxMessagesToFetch)
	if err != nil {
		return nil, errors.Wrapf(err, "_getPaginatedMessageEntriesForGroupChatThreadRecursionSafe: "+
			"Problem gettign message entries from db for groupChatThread (%v), startingTimestamp (%v), maxMessagesToFetch (%v)",
			groupChatThread, startingTimestamp, maxMessagesToFetch)
	}

	// We define a predicate that check whether we fetched maximum number of message entries. We might drop some entries later
	// when we combine the db message entries with the ones fetched from the UtxoView.
	isListFilled := uint64(len(dbMessageEntries)) >= maxMessagesToFetch
	var lastKnownDbTimestamp uint64
	if len(dbMessageEntries) > 0 {
		lastKnownDbTimestamp = dbMessageEntries[len(dbMessageEntries)-1].TimestampNanos
	}

	// Finally, there is a possibility that there have been additional messages send during the current block,
	// and we need to make sure we include them in the list of messages we return. We do this by iterating over all
	// the members in the current UtxoView and inserting them into the list of members we return.
	existingMessagesMap := make(map[uint64]*NewMessageEntry)
	for _, message := range dbMessageEntries {
		messageCopy := *message
		existingMessagesMap[message.TimestampNanos] = &messageCopy
	}

	filteredUtxoViewMessages := make(map[uint64]*NewMessageEntry)
	for messageKeyIter, messageEntryIter := range bav.GroupChatMessagesIndex {

		// Make sure the utxoView message matches our current thread.
		isValidThread := bytes.Equal(messageKeyIter.GroupOwnerPublicKey.ToBytes(), groupChatThread.AccessGroupOwnerPublicKey.ToBytes()) &&
			bytes.Equal(messageKeyIter.GroupKeyName.ToBytes(), groupChatThread.AccessGroupKeyName.ToBytes())
		if !isValidThread {
			continue
		}

		// Make sure the message has a timestamp that is smaller than our starting timestamp.
		isValidTimestamp := startingTimestamp > messageKeyIter.TimestampNanos
		if !isValidTimestamp {
			continue
		}

		// In case we already fetched the maximum number of messages, we just need to check whether the current message
		// timestamp is greater or equal to the last message we fetched from the DB. If it isn't, we can skip. The reason is that
		// if we added a message with smaller timestamp, there is a chance there might be some messages with smaller
		// timestamp still present in the db, which we shouldn't skip.
		var isGreaterOrEqualThanEndTimestamp bool
		if isListFilled {
			isGreaterOrEqualThanEndTimestamp = messageKeyIter.TimestampNanos >= lastKnownDbTimestamp
			if !isGreaterOrEqualThanEndTimestamp {
				continue
			}
		}

		messageEntry := *messageEntryIter
		filteredUtxoViewMessages[messageEntry.TimestampNanos] = &messageEntry
	}

	finalMessageEntries := []*NewMessageEntry{}
	for messageKeyIter, messageEntryIter := range existingMessagesMap {
		copyMessageEntry := *messageEntryIter
		if utxoMessage, exists := filteredUtxoViewMessages[messageKeyIter]; exists {
			if utxoMessage.isDeleted {
				continue
			} else {
				copyMessageEntry = *utxoMessage
			}
		}
		finalMessageEntries = append(finalMessageEntries, &copyMessageEntry)
	}
	for utxoMessageKeyIter, utxoMessageEntry := range filteredUtxoViewMessages {
		if _, exists := existingMessagesMap[utxoMessageKeyIter]; exists {
			continue
		}
		if utxoMessageEntry.isDeleted {
			continue
		}
		copyUtxoMessage := *utxoMessageEntry
		finalMessageEntries = append(finalMessageEntries, &copyUtxoMessage)
	}
	// Sort messages by timestamp in descending order.
	sort.Slice(finalMessageEntries, func(ii, jj int) bool {
		return finalMessageEntries[ii].TimestampNanos > finalMessageEntries[jj].TimestampNanos
	})

	// After iterating over all the messages in the current UtxoView, there is a possibility that we now have less messages
	// than the maxMessagesToFetch, due to deleted messages. In this case, we need to fetch more members from the DB,
	// which we will do with the magic of recursion.
	if isListFilled && len(finalMessageEntries) < int(maxMessagesToFetch) &&
		lastKnownDbTimestamp < startingTimestamp {

		// Note this recursive call will never lead to an infinite loop because the startingTimestamp
		// will be growing with each recursive call, and because we are checking for isListFilled with
		// maxMessagesToFetch > 0. But just in case we add a sanity-check parameter maxDepth to break long recursive calls.
		remainingMessages, err := bav._getPaginatedMessageEntriesForGroupChatThreadRecursionSafe(
			groupChatThread, lastKnownDbTimestamp, maxMessagesToFetch-uint64(len(finalMessageEntries)), maxDepth-1)
		if err != nil {
			return nil, errors.Wrapf(err, "_getPaginatedMessageEntriesForGroupChatThreadRecursionSafe: "+
				"Problem getting recursion message entries for the next message with "+
				"groupChatThread (%v), startingTimestamp (%v)", groupChatThread, startingTimestamp)
		}
		finalMessageEntries = append(finalMessageEntries, remainingMessages...)
	}

	if len(finalMessageEntries) > int(maxMessagesToFetch) {
		// Timestamps will be in ascending order, so we slice the smallest timestamps.
		finalMessageEntries = finalMessageEntries[:maxMessagesToFetch]
	}
	return finalMessageEntries, nil
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
// GroupChatThreadIndex
// ==================================================================

func (bav *UtxoView) getGroupChatThreadExistence(groupKey AccessGroupId) (*GroupChatThreadExistence, error) {
	mapValue, existsMapValue := bav.GroupChatThreadIndex[groupKey]
	if existsMapValue {
		return mapValue, nil
	}

	dbAdapter := bav.GetDbAdapter()
	dbThreadExists, err := dbAdapter.CheckGroupChatThreadExistence(groupKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupChatThreadExistence: ")
	}

	if dbThreadExists != nil {
		bav.GroupChatThreadIndex[groupKey] = dbThreadExists
	}
	return dbThreadExists, nil
}

func (bav *UtxoView) GetAllUserGroupChatThreads(userAccessGroupOwnerPublicKey PublicKey) (
	_groupChatThreads []*AccessGroupId, _err error) {

	accessGroupIdsOwned, accessGroupIdsMember, err := bav.GetAllAccessGroupIdsForUser(userAccessGroupOwnerPublicKey.ToBytes())
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllUserGroupChatThreads: Problem getting all "+
			"user group ids for user public key %v", userAccessGroupOwnerPublicKey)
	}

	// There might be repetitive access group Ids among the groups registered
	// by the user and those in which the user is a member. This is because it is
	// possible to add oneself as a member to one's own group.
	accessGroupIdMap := make(map[AccessGroupId]struct{})
	for _, groupIdIter := range accessGroupIdsOwned {
		groupId := *groupIdIter
		accessGroupIdMap[groupId] = struct{}{}
	}
	for _, groupIdIter := range accessGroupIdsMember {
		groupId := *groupIdIter
		accessGroupIdMap[groupId] = struct{}{}
	}

	// Now, we will compare the access groups we fetched for a user with the group chat thread existence entries
	// to filter out all the access groups that were never used as group chats.
	groupChatKeys := make(map[AccessGroupId]struct{})
	dbAdapter := bav.GetDbAdapter()
	for groupIdIter := range accessGroupIdMap {
		groupId := groupIdIter
		existence, err := dbAdapter.CheckGroupChatThreadExistence(groupId)
		if err != nil {
			return nil, errors.Wrapf(err, "GetAllUserGroupChatThreads: Problem checking group chat thread existence "+
				"for access group id: %v", groupId)
		}
		if existence == nil || existence.isDeleted {
			continue
		}
		groupChatKeys[groupId] = struct{}{}
	}

	// Now iterate through the utxoView mapping to discard any deleted group chat threads.
	for groupIdIter, groupExistence := range bav.GroupChatThreadIndex {
		groupId := groupIdIter
		if _, ok := accessGroupIdMap[groupId]; !ok {
			continue
		}
		if groupExistence.isDeleted {
			delete(groupChatKeys, groupId)
		} else {
			groupChatKeys[groupId] = struct{}{}
		}
	}

	// Serialize the group chat keys map into an array
	var groupChatsFound []*AccessGroupId
	for groupIdIter := range groupChatKeys {
		groupId := groupIdIter
		groupChatsFound = append(groupChatsFound, &groupId)
	}

	return groupChatsFound, nil
}

func (bav *UtxoView) setGroupChatThreadIndex(groupKey AccessGroupId, existence GroupChatThreadExistence) {
	existenceCopy := existence
	bav.GroupChatThreadIndex[groupKey] = &existenceCopy
}

func (bav *UtxoView) deleteGroupChatThreadIndex(groupKey AccessGroupId) {
	existence := MakeGroupChatThreadExistence()
	existence.isDeleted = true
	bav.setGroupChatThreadIndex(groupKey, existence)
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

// ==================================================================
// DmThreadIndex
// ==================================================================

func (bav *UtxoView) getDmThreadExistence(dmThreadKey DmThreadKey) (*DmThreadExistence, error) {
	mapValue, existsMapValue := bav.DmThreadIndex[dmThreadKey]
	if existsMapValue {
		return mapValue, nil
	}

	dbAdapter := bav.GetDbAdapter()
	dbThreadExists, err := dbAdapter.CheckDmThreadExistence(dmThreadKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getDmThreadExistence: ")
	}

	if dbThreadExists != nil {
		bav.DmThreadIndex[dmThreadKey] = dbThreadExists
	}
	return dbThreadExists, nil
}

func (bav *UtxoView) GetAllUserDmThreads(userAccessGroupOwnerPublicKey PublicKey) (_dmThreads []*DmThreadKey, _err error) {
	dbAdapter := bav.GetDbAdapter()
	dmThreads, err := dbAdapter.GetAllUserDmThreads(userAccessGroupOwnerPublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllUserDmThreads: Problem getting dm threads from db "+
			"for user: %v", userAccessGroupOwnerPublicKey)
	}

	// Get UtxoView entries
	dmThreadKeyMap := make(map[DmThreadKey]struct{})
	for _, dmThreadKey := range dmThreads {
		dmThreadKeyMap[*dmThreadKey] = struct{}{}
	}

	// Iterate over UtxoView mappings
	for dmThreadKeyIter, dmThreadExistence := range bav.DmThreadIndex {
		if !bytes.Equal(dmThreadKeyIter.userGroupOwnerPublicKey.ToBytes(), userAccessGroupOwnerPublicKey.ToBytes()) {
			continue
		}

		dmThreadKey := dmThreadKeyIter
		if dmThreadExistence.isDeleted {
			delete(dmThreadKeyMap, dmThreadKey)
			continue
		}
		dmThreadKeyMap[dmThreadKey] = struct{}{}
	}

	// Convert map to slice
	dmThreadKeys := []*DmThreadKey{}
	for dmThreadKey := range dmThreadKeyMap {
		dmThreadKeyCopy := dmThreadKey
		dmThreadKeys = append(dmThreadKeys, &dmThreadKeyCopy)
	}

	return dmThreadKeys, nil
}

func (bav *UtxoView) GetPaginatedMessageEntriesForDmThread(dmThread DmThreadKey, startingTimestamp uint64,
	maxMessagesToFetch uint64) (_messageEntries []*NewMessageEntry, _err error) {

	return bav._getPaginatedMessageEntriesForDmThreadRecursionSafe(dmThread, startingTimestamp,
		maxMessagesToFetch, MaxDmMessageRecursionDepth)
}

func (bav *UtxoView) _getPaginatedMessageEntriesForDmThreadRecursionSafe(dmThread DmThreadKey, startingTimestamp uint64,
	maxMessagesToFetch uint64, maxDepth uint32) (_messageEntries []*NewMessageEntry, _err error) {

	if maxMessagesToFetch == 0 {
		return nil, nil
	}
	// This function can make recursive calls to itself. We use a depth counter to prevent infinite recursion
	// (which shouldn't happen anyway, but better safe than sorry, right?).
	if maxDepth == 0 {
		return nil, errors.Wrapf(RuleErrorNewMessageGetDmMessagesRecursionLimit,
			"_getPaginatedMessageEntriesForDmThreadRecursionSafe: maxDepth == 0")
	}

	// Fetch the message entries from db.
	dbAdapter := bav.GetDbAdapter()
	dbMessageEntries, err := dbAdapter.GetPaginatedMessageEntriesForDmThread(dmThread, startingTimestamp, maxMessagesToFetch)
	if err != nil {
		return nil, errors.Wrapf(err, "_getPaginatedMessageEntriesForDmThreadRecursionSafe:"+
			"Problem getting message entries from db for dmThreadKey (%v), startingTimestamp (%v), maxMessageToFetch (%v)",
			dmThread, startingTimestamp, maxMessagesToFetch)
	}

	// We define a predicate that checks whether we fetched maximum number of message entries. We might drop some entries later
	// when we combine the db message entries with the ones fetched from the UtxoView.
	isListFilled := uint64(len(dbMessageEntries)) == maxMessagesToFetch
	var lastKnownDbTimestamp uint64
	if len(dbMessageEntries) > 0 {
		lastKnownDbTimestamp = dbMessageEntries[len(dbMessageEntries)-1].TimestampNanos
	}

	// Finally, there is a possibility that there have been additional messages send during the current block,
	// and we need to make sure we include them in the list of messages we return. We do this by iterating over all
	// the members in the current UtxoView and inserting them into the list of members we return.
	existingMessagesMap := make(map[DmMessageKey]*NewMessageEntry)
	for _, message := range dbMessageEntries {
		messageKey := MakeDmMessageKey(*message.SenderAccessGroupOwnerPublicKey, *message.SenderAccessGroupKeyName,
			*message.RecipientAccessGroupOwnerPublicKey, *message.RecipientAccessGroupKeyName, message.TimestampNanos)
		messageCopy := *message
		existingMessagesMap[messageKey] = &messageCopy
	}

	filteredUtxoViewMessages := make(map[DmMessageKey]*NewMessageEntry)
	for dmMessageKeyIter, messageEntryIter := range bav.DmMessagesIndex {
		threadMessageKey := MakeDmMessageKeyFromDmThreadKey(dmThread)

		// Make sure the utxoView message matches our current thread.
		isValidThread := bytes.Equal(dmMessageKeyIter.MinorGroupOwnerPublicKey.ToBytes(), threadMessageKey.MinorGroupOwnerPublicKey.ToBytes()) &&
			bytes.Equal(dmMessageKeyIter.MinorGroupKeyName.ToBytes(), threadMessageKey.MinorGroupKeyName.ToBytes()) &&
			bytes.Equal(dmMessageKeyIter.MajorGroupOwnerPublicKey.ToBytes(), threadMessageKey.MajorGroupOwnerPublicKey.ToBytes()) &&
			bytes.Equal(dmMessageKeyIter.MajorGroupKeyName.ToBytes(), threadMessageKey.MajorGroupKeyName.ToBytes())
		if !isValidThread {
			continue
		}

		// Make sure the message has a timestamp that is smaller than our starting timestamp.
		isValidTimestamp := startingTimestamp > dmMessageKeyIter.TimestampNanos
		if !isValidTimestamp {
			continue
		}

		// In case we already fetched the maximum number of messages, we just need to check whether the current message
		// timestamp is greater or equal to the last message we fetched from the DB. If it isn't, we can skip. The reason is that
		// if we added a message with smaller timestamp, there is a chance there might be some messages with smaller
		// timestamp still present in the db, which we shouldn't skip.
		var isGreaterOrEqualThanEndTimestamp bool
		if isListFilled {
			isGreaterOrEqualThanEndTimestamp = dmMessageKeyIter.TimestampNanos >= lastKnownDbTimestamp
			if !isGreaterOrEqualThanEndTimestamp {
				continue
			}
		}

		messageEntry := *messageEntryIter
		dmMessageKey := dmMessageKeyIter
		filteredUtxoViewMessages[dmMessageKey] = &messageEntry
	}

	finalMessageEntries := []*NewMessageEntry{}
	for messageKeyIter, messageEntryIter := range existingMessagesMap {
		copyMessageEntry := *messageEntryIter
		if utxoMessage, exists := filteredUtxoViewMessages[messageKeyIter]; exists {
			if utxoMessage.isDeleted {
				continue
			} else {
				copyMessageEntry = *utxoMessage
			}
		}
		finalMessageEntries = append(finalMessageEntries, &copyMessageEntry)
	}
	for utxoMessageKeyIter, utxoMessageEntry := range filteredUtxoViewMessages {
		if _, exists := existingMessagesMap[utxoMessageKeyIter]; exists {
			continue
		}
		if utxoMessageEntry.isDeleted {
			continue
		}
		copyUtxoMessage := *utxoMessageEntry
		finalMessageEntries = append(finalMessageEntries, &copyUtxoMessage)
	}
	// Sort messages by timestamp in descending order.
	sort.Slice(finalMessageEntries, func(ii, jj int) bool {
		return finalMessageEntries[ii].TimestampNanos > finalMessageEntries[jj].TimestampNanos
	})

	// After iterating over all the messages in the current UtxoView, there is a possibility that we now have less messages
	// than the maxMessagesToFetch, due to deleted messages. In this case, we need to fetch more members from the DB,
	// which we will do with the magic of recursion.
	if isListFilled && len(finalMessageEntries) < int(maxMessagesToFetch) &&
		lastKnownDbTimestamp < startingTimestamp {

		// Note this recursive call will never lead to an infinite loop because the startingTimestamp
		// will be growing with each recursive call, and because we are checking for isListFilled with
		// maxMessagesToFetch > 0. But just in case we add a sanity-check parameter maxDepth to break long recursive calls.
		remainingMessages, err := bav._getPaginatedMessageEntriesForDmThreadRecursionSafe(
			dmThread, lastKnownDbTimestamp, maxMessagesToFetch-uint64(len(finalMessageEntries)), maxDepth-1)
		if err != nil {
			return nil, errors.Wrapf(err, "_getPaginatedMessageEntriesForDmThreadRecursionSafe: "+
				"Problem fetching recursion message entries for the next message with "+
				"dmThreadKey (%v), lastKnownDbTimestamp (%v)", dmThread, lastKnownDbTimestamp)
		}
		finalMessageEntries = append(finalMessageEntries, remainingMessages...)
	}

	if len(finalMessageEntries) > int(maxMessagesToFetch) {
		finalMessageEntries = finalMessageEntries[:maxMessagesToFetch]
	}
	return finalMessageEntries, nil
}

func (bav *UtxoView) setDmThreadIndex(dmThreadKey DmThreadKey, existence DmThreadExistence) {
	existenceCopy := existence
	bav.DmThreadIndex[dmThreadKey] = &existenceCopy
}

func (bav *UtxoView) deleteDmThreadIndex(dmThreadKey DmThreadKey) {
	existence := MakeDmThreadExistence()
	existence.isDeleted = true
	bav.setDmThreadIndex(dmThreadKey, existence)
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
	var prevDmThreadExistence *DmThreadExistence
	var prevGroupChatThreadExistence *GroupChatThreadExistence

	switch txMeta.NewMessageOperation {
	case NewMessageOperationCreate:
		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			if bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
				return 0, 0, nil, RuleErrorNewMessageDmSenderAndRecipientCannotBeTheSame
			}

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
			// Because DM messages between two users are indexed by <AGroupId, BGroupId>, we need to store
			// mirror entries for both <AGroupId, BGroupId> and <BGroupId, AGroupId>. However, we don't
			// necessarily need to store two messages for the same user. To store messages, it suffices
			// to find lexicographical minimum of AGroupId.ToBytes(), BGroupId.ToBytes and store the message
			// under <minGroupId, maxGroupId>. Next, in a different table, we store pointers to this message
			// under <AGroupId, BGroupId> and <BGroupId, AGroupId>. This halves the space with an overhead
			// of just a single additional DB key-only lookup operation, which is rather efficient.
			dmThreadKeySender, err := MakeDmThreadKeyFromMessageEntry(messageEntry, false)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"making dm thread key from message entry: %v", messageEntry)
			}
			// Make a dm thread key for the sender.
			dmThreadKeyRecipient, err := MakeDmThreadKeyFromMessageEntry(messageEntry, true)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"making dm thread key for sender from message entry: %v", messageEntry)
			}
			dmThread, err := bav.getDmThreadExistence(dmThreadKeySender)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"getting dm thread existence from index with dm thread key %v: ", dmThreadKeySender)
			}
			// If thread exists, we should set the prevDmThreadExistence for the UtxoOperation.
			if dmThread != nil && !dmThread.isDeleted {
				dmThreadCopy := *dmThread
				prevDmThreadExistence = &dmThreadCopy
			} else {
				// If thread does not exist, we should set the prevDmThreadExistence to nil.
				// This means we are dealing with the first message between these two users.
				prevDmThreadExistence = nil
			}
			err = bav.setDmMessagesIndex(messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"setting dm message in index with dm message key %v: ", dmMessageKey)
			}

			bav.setDmThreadIndex(dmThreadKeySender, MakeDmThreadExistence())
			bav.setDmThreadIndex(dmThreadKeyRecipient, MakeDmThreadExistence())
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
			// We have previously verified the existence of access groups both for the sender and the recipient.
			// If the sender is not the owner of the group chat, we need to verify that they are a member of the group.
			if !bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
				groupMemberEntry, err := bav.GetAccessGroupMemberEntry(&txMeta.SenderAccessGroupOwnerPublicKey,
					&txMeta.RecipientAccessGroupOwnerPublicKey, &txMeta.RecipientAccessGroupKeyName)
				if err != nil {
					return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
						"getting group member entry for sender public key (%v) and recipient public key (%v) and recipient group name (%v)",
						txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName)
				}
				if groupMemberEntry == nil || groupMemberEntry.isDeleted {
					return 0, 0, nil, errors.Wrapf(RuleErrorNewMessageGroupChatMemberEntryDoesntExist,
						"_connectNewMessage: Sender (%v) is not a member of the group chat with ownerPublicKey (%v), groupKeyName (%v)",
						txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName)
				}
			}

			// Fetch the group chat thread existence entry, which is indexed by the recipient's access group.
			groupChatAccessGroupId := NewAccessGroupId(&txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName.ToBytes())
			// Sanity-check that the group chat thread we're reverting was properly set.
			groupChatThread, err := bav.getGroupChatThreadExistence(*groupChatAccessGroupId)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"getting group chat thread existence from index with group chat thread key %v: ", groupChatAccessGroupId)
			}
			// If thread exists, we should set the prevGroupChatThreadExistence for the UtxoOperation.
			if groupChatThread != nil && !groupChatThread.isDeleted {
				groupChatThreadCopy := *groupChatThread
				prevGroupChatThreadExistence = &groupChatThreadCopy
			} else {
				// If thread does not exist, we should set the prevGroupChatThreadExistence to nil.
				// This means we are dealing with the first message in this group chat.
				prevGroupChatThreadExistence = nil
			}

			err = bav.setGroupChatMessagesIndex(messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: Problem "+
					"setting group chat message in index with group chat message key %v: ", groupChatMessageKey)
			}
			bav.setGroupChatThreadIndex(*groupChatAccessGroupId, MakeGroupChatThreadExistence())
		default:
			return 0, 0, nil, errors.Wrapf(
				RuleErrorNewMessageUnknownMessageType, "_connectNewMessage: unknown message type")
		}
	case NewMessageOperationUpdate:
		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			if bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
				return 0, 0, nil, RuleErrorNewMessageDmSenderAndRecipientCannotBeTheSame
			}

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
			// Since a message exists, we know that the DM thread must also exist.
			// We should set the prevDmThreadExistence to exists for the UtxoOperation.
			dmThreadExists := MakeDmThreadExistence()
			prevDmThreadExistence = &dmThreadExists

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

			// Since a message exists, we know that the group chat thread must also exist.
			// We should set the prevGroupChatThreadExistence to exists for the UtxoOperation.
			groupChatThreadExists := MakeGroupChatThreadExistence()
			prevGroupChatThreadExistence = &groupChatThreadExists
		default:
			return 0, 0, nil, errors.Wrapf(
				RuleErrorNewMessageUnknownMessageType, "_connectNewMessage: unknown message type")
		}
	default:
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageUnknownOperationType, "_connectNewMessage: unknown new message operation type")
	}

	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                         OperationTypeNewMessage,
		PrevNewMessageEntry:          prevNewMessageEntry,
		PrevDmThreadExistence:        prevDmThreadExistence,
		PrevGroupChatThreadExistence: prevGroupChatThreadExistence,
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

			// Delete the dm thread existence index.
			dmThreadKeySender, err := MakeDmThreadKeyFromMessageEntry(dmMessage, false)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem making dm thread key for "+
					"message entry: %v", dmMessage)
			}
			dmThreadKeyRecipient, err := MakeDmThreadKeyFromMessageEntry(dmMessage, true)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem making dm thread key for "+
					"message entry: %v", dmMessage)
			}
			dmThread, err := bav.getDmThreadExistence(dmThreadKeySender)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem getting dm thread existence from "+
					"index with dm thread key %v: ", dmThreadKeySender)
			}
			if dmThread != nil && dmThread.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: DM thread existence is deleted for "+
					"dm thread key %v", dmThread)
			}

			err = bav.deleteDmMessagesIndex(dmMessage)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem deleting dm message index: ")
			}
			// If prevUtxoOp is set to nil, we should delete the thread from the db.
			if prevUtxoOp.PrevDmThreadExistence == nil {
				bav.deleteDmThreadIndex(dmThreadKeySender)
				bav.deleteDmThreadIndex(dmThreadKeyRecipient)
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

			// Sanity-check that the group chat thread we're reverting was properly set.
			groupChatAccessGroupId := NewAccessGroupId(&txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName.ToBytes())
			groupChatThread, err := bav.getGroupChatThreadExistence(*groupChatAccessGroupId)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem getting group chat thread existence from "+
					"index with group chat thread key %v: ", groupChatAccessGroupId)
			}
			if groupChatThread != nil && groupChatThread.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: Group chat thread existence is deleted for "+
					"group chat thread key %v", groupChatAccessGroupId)
			}

			err = bav.deleteGroupChatMessagesIndex(groupChatMessage)
			if err != nil {
				return errors.Wrapf(err, "_disconnectNewMessage: Problem deleting group chat message index: ")
			}

			// If prevUtxoOp is set to nil, we should delete the thread from the db.
			if prevUtxoOp.PrevGroupChatThreadExistence == nil {
				bav.deleteGroupChatThreadIndex(*groupChatAccessGroupId)
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
			// Dm thread index must exist for new message update.
			if prevUtxoOp.PrevDmThreadExistence == nil || prevUtxoOp.PrevDmThreadExistence.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: DM thread existence is nil or deleted for "+
					"dm thread key %v", dmMessageKey)
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
			// Group chat thread index must exist for new message update.
			if prevUtxoOp.PrevGroupChatThreadExistence == nil || prevUtxoOp.PrevGroupChatThreadExistence.isDeleted {
				return fmt.Errorf("_disconnectNewMessage: Group chat thread existence is nil or deleted for "+
					"group chat thread key %v", groupChatMessageKey)
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
