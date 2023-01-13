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

// getGroupChatMessagesIndex returns the NewMessageEntry for the given group chat message key.
// The messages are indexed by the access group id of the group chat with a timestamp, i.e.:
// 	<AccessGroupOwnerPublicKey, GroupKeyName, TimestampNanos> -> NewMessageEntry
func (bav *UtxoView) getGroupChatMessagesIndex(groupChatMessageKey GroupChatMessageKey) (*NewMessageEntry, error) {

	// First, check the in-memory index.
	mapValue, existsMapValue := bav.GroupChatMessagesIndex[groupChatMessageKey]
	if existsMapValue {
		return mapValue, nil
	}

	// If we didn't find it in the in-memory index, check the database.
	dbAdapter := bav.GetDbAdapter()
	dbMessageEntry, err := dbAdapter.GetGroupChatMessageEntry(groupChatMessageKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupChatMessagesIndex: ")
	}
	// If we found it in the database, add it to the in-memory index.
	if dbMessageEntry != nil {
		if err := bav.setGroupChatMessagesIndex(dbMessageEntry); err != nil {
			return nil, errors.Wrapf(err, "getGroupChatMessagesIndex: ")
		}
	}
	return dbMessageEntry, nil
}

// GetPaginatedMessageEntriesForGroupChatThread returns a list of paginated message entries for a given group chat thread.
// The following constraints are applied:
// (1.) The startingTimestamp is the largest timestamp that we want to include in the results
// (2.) Fetch at most maxMessagesToFetch messages.
// (3.) _messageEntries are sorted by timestamp in descending order. That is, the most recent message is at index [0].
//
// In other words, the returned _messageEntries will follow these constraints:
// 1. _messageEntries[0].TimestampNanos <= startingMaxTimestamp
// 2. len(_messageEntries) <= maxMessagesToFetch
// 3. _messageEntries[i].TimestampNanos > _messageEntries[i+1].TimestampNanos
func (bav *UtxoView) GetPaginatedMessageEntriesForGroupChatThread(groupChatThread AccessGroupId, startingMaxTimestamp uint64,
	maxMessagesToFetch uint64) (_messageEntries []*NewMessageEntry, _err error) {

	return bav._getPaginatedMessageEntriesForGroupChatThreadRecursionSafe(groupChatThread, startingMaxTimestamp,
		maxMessagesToFetch, MaxGroupChatMessageRecursionDepth)
}

// _getPaginatedMessageEntriesForGroupChatThreadRecursionSafe is a helper function for GetPaginatedMessageEntriesForGroupChatThread.
// It adds a recursion depth counter to prevent infinite recursion. This paginated fetch will first fetch entries from the
// db and then combine them with the in-memory map of group chat message entries. If the in-memory map indicates that some
// db entries were deleted in this view, we might need to fetch more entries from the db to fill in the gaps.
// This is where we will make a recursive call to this function. The maxDepth parameter makes sure we don't recurse forever
// in case there is a bug in the code (though there isn't one).
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
		isValidThread := bytes.Equal(messageKeyIter.AccessGroupOwnerPublicKey.ToBytes(), groupChatThread.AccessGroupOwnerPublicKey.ToBytes()) &&
			bytes.Equal(messageKeyIter.AccessGroupKeyName.ToBytes(), groupChatThread.AccessGroupKeyName.ToBytes())
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

	// Now that we have all the messages db and utxoView, we need to combine them and sort them by timestamp.
	finalMessageEntries := []*NewMessageEntry{}
	for messageKeyIter, messageEntryIter := range existingMessagesMap {
		copyMessageEntry := *messageEntryIter
		if utxoMessage, exists := filteredUtxoViewMessages[messageKeyIter]; exists {
			// If the message exists in the utxoView, we need to check whether it was deleted. If it was deleted,
			// we need to skip it.
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
		// Timestamps will be in descending order, so we slice the smallest timestamps.
		finalMessageEntries = finalMessageEntries[:maxMessagesToFetch]
	}
	return finalMessageEntries, nil
}

// setGroupChatMessagesIndex sets the GroupChatMessagesIndex for the given messageKey to the given messageEntry.
func (bav *UtxoView) setGroupChatMessagesIndex(messageEntry *NewMessageEntry) error {
	// Sanity check that the messageEntry is not nil.
	if messageEntry == nil {
		return fmt.Errorf("setGroupChatMessagesIndex: called with nil messageEntry")
	}

	// Sanity check that the messageEntry fields are not nil.
	if messageEntry.RecipientAccessGroupOwnerPublicKey == nil || messageEntry.RecipientAccessGroupKeyName == nil {
		return fmt.Errorf("setGroupChatMessagesIndex: called with nil recipient data")
	}

	// Set the GroupChatMessagesIndex with the provided messageEntry.
	groupChatMessageKey := MakeGroupChatMessageKey(
		*messageEntry.RecipientAccessGroupOwnerPublicKey, *messageEntry.RecipientAccessGroupKeyName, messageEntry.TimestampNanos)
	bav.GroupChatMessagesIndex[groupChatMessageKey] = messageEntry
	return nil
}

// deleteGroupChatMessagesIndex deletes the GroupChatMessagesIndex for the given messageKey.
func (bav *UtxoView) deleteGroupChatMessagesIndex(messageEntry *NewMessageEntry) error {

	// Sanity check that the messageEntry is not nil.
	if messageEntry == nil {
		return fmt.Errorf("deleteGroupChatMessagesIndex: called with nil messageEntry")
	}

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

// getGroupChatThreadExistence returns the GroupChatThreadExistence entry for the given groupKey AccessGroupId.
func (bav *UtxoView) getGroupChatThreadExistence(groupKey AccessGroupId) (*GroupChatThreadExistence, error) {
	// Fetch the GroupChatThreadExistence entry from the UtxoView.
	mapValue, existsMapValue := bav.GroupChatThreadIndex[groupKey]
	if existsMapValue {
		return mapValue, nil
	}
	// If the GroupChatThreadExistence entry does not exist in the UtxoView, fetch it from the DB.
	dbAdapter := bav.GetDbAdapter()
	dbThreadExists, err := dbAdapter.CheckGroupChatThreadExistence(groupKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getGroupChatThreadExistence: ")
	}

	// If the GroupChatThreadExistence entry exists, update the UtxoView with the entry.
	if dbThreadExists != nil {
		bav.GroupChatThreadIndex[groupKey] = dbThreadExists
	}
	return dbThreadExists, nil
}

// GetAllUserGroupChatThreads returns all the group chat threads that the user is a participant of, this includes potentially
// both access group registered by the user, and access groups that the user is a member of.
func (bav *UtxoView) GetAllUserGroupChatThreads(userAccessGroupOwnerPublicKey PublicKey) (
	_groupChatThreads []*AccessGroupId, _err error) {

	// We will fetch all access groups that the user registered, and all access groups that the user is a member of.
	// We will then filter out the access groups for which there is no existing group chat thread existence entry.
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

// setGroupChatThreadExistence sets the GroupChatThreadExistence entry for the given groupKey AccessGroupId.
func (bav *UtxoView) setGroupChatThreadIndex(groupKey AccessGroupId, existence GroupChatThreadExistence) {
	existenceCopy := existence
	bav.GroupChatThreadIndex[groupKey] = &existenceCopy
}

// deleteGroupChatThreadExistence deletes the GroupChatThreadExistence entry for the given groupKey AccessGroupId.
func (bav *UtxoView) deleteGroupChatThreadIndex(groupKey AccessGroupId) {
	existence := MakeGroupChatThreadExistence()
	existence.isDeleted = true
	bav.setGroupChatThreadIndex(groupKey, existence)
}

// ==================================================================
// DmMessagesIndex
// ==================================================================

// getDmMessagesIndex returns the DmMessagesIndex entry for the given DmMessageKey.
func (bav *UtxoView) getDmMessagesIndex(dmMessageKey DmMessageKey) (*NewMessageEntry, error) {
	// Fetch the DmMessagesIndex entry from the UtxoView.
	mapValue, existsMapValue := bav.DmMessagesIndex[dmMessageKey]
	if existsMapValue {
		return mapValue, nil
	}

	// If the DmMessagesIndex entry does not exist in the UtxoView, fetch it from the DB.
	dbAdapter := bav.GetDbAdapter()
	dbMessageEntry, err := dbAdapter.GetDmMessageEntry(dmMessageKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getDmMessagesIndex: ")
	}

	// If the DmMessagesIndex entry exists, update the UtxoView with the entry.
	if dbMessageEntry != nil {
		if err := bav.setDmMessagesIndex(dbMessageEntry); err != nil {
			return nil, errors.Wrapf(err, "getDmMessagesIndex: ")
		}
	}
	return dbMessageEntry, nil
}

// setDmMessagesIndex sets the DmMessagesIndex entry for the given NewMessageEntry.
func (bav *UtxoView) setDmMessagesIndex(messageEntry *NewMessageEntry) error {
	// Sanity check that the message entry is not nil.
	if messageEntry == nil {
		return fmt.Errorf("setDmMessagesIndex: called with nil messageEntry")
	}

	// Sanity check that the message entry fields are not nil in the DM message.
	if messageEntry.SenderAccessGroupOwnerPublicKey == nil || messageEntry.SenderAccessGroupKeyName == nil ||
		messageEntry.RecipientAccessGroupOwnerPublicKey == nil || messageEntry.RecipientAccessGroupKeyName == nil {

		return fmt.Errorf("setDmMessagesIndex: called with nil sender or recipient data")
	}

	// Set the DmMessagesIndex entry in the UtxoView.
	dmMessageKey := MakeDmMessageKeyForSenderRecipient(*messageEntry.SenderAccessGroupOwnerPublicKey, *messageEntry.SenderAccessGroupKeyName,
		*messageEntry.RecipientAccessGroupOwnerPublicKey, *messageEntry.RecipientAccessGroupKeyName, messageEntry.TimestampNanos)

	bav.DmMessagesIndex[dmMessageKey] = messageEntry
	return nil
}

// deleteDmMessagesIndex deletes the DmMessagesIndex entry for the given DmMessageKey.
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

// getDmThreadIndex returns the DmThreadExistence entry for the given DmThreadKey.
func (bav *UtxoView) getDmThreadExistence(dmThreadKey DmThreadKey) (*DmThreadExistence, error) {
	// Fetch the DmThreadExistence entry from the UtxoView.
	mapValue, existsMapValue := bav.DmThreadIndex[dmThreadKey]
	if existsMapValue {
		return mapValue, nil
	}

	// If the DmThreadExistence entry does not exist in the UtxoView, fetch it from the DB.
	dbAdapter := bav.GetDbAdapter()
	dbThreadExists, err := dbAdapter.CheckDmThreadExistence(dmThreadKey)
	if err != nil {
		return nil, errors.Wrapf(err, "getDmThreadExistence: ")
	}

	// If the DmThreadExistence entry exists, update the UtxoView with the entry.
	if dbThreadExists != nil {
		bav.DmThreadIndex[dmThreadKey] = dbThreadExists
	}
	return dbThreadExists, nil
}

// GetAllUserDmThreads returns all the DM threads that the user is a part of. This is done by looking up all of the
// DM threads that the user has in the db in DmThreadIndex.
func (bav *UtxoView) GetAllUserDmThreads(userAccessGroupOwnerPublicKey PublicKey) (_dmThreads []*DmThreadKey, _err error) {
	// First, get all the DM threads that the user is a part of from db.
	dbAdapter := bav.GetDbAdapter()
	dmThreads, err := dbAdapter.GetAllUserDmThreads(userAccessGroupOwnerPublicKey)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAllUserDmThreads: Problem getting dm threads from db "+
			"for user: %v", userAccessGroupOwnerPublicKey)
	}

	// Add all the db DM threads to a map so we can later easily compare them to the DM threads in the UtxoView.
	dmThreadKeyMap := make(map[DmThreadKey]struct{})
	for _, dmThreadKey := range dmThreads {
		dmThreadKeyMap[*dmThreadKey] = struct{}{}
	}

	// Iterate over DmThreadIndex mappings. We will eliminate any mappings that are deleted in the DmThreadIndex, and
	// add any mappings that are not in the db but are in the UtxoView.
	for dmThreadKeyIter, dmThreadExistenceIter := range bav.DmThreadIndex {
		if !bytes.Equal(dmThreadKeyIter.userGroupOwnerPublicKey.ToBytes(), userAccessGroupOwnerPublicKey.ToBytes()) {
			continue
		}

		dmThreadKey := dmThreadKeyIter
		// If the mapping is deleted, remove it from the map.
		if dmThreadExistenceIter.isDeleted {
			delete(dmThreadKeyMap, dmThreadKey)
			continue
		}
		// If the mapping is not in the db, add it to the map.
		dmThreadKeyMap[dmThreadKey] = struct{}{}
	}

	// Convert the dmThreadKeys, now final, map to a slice
	dmThreadKeys := []*DmThreadKey{}
	for dmThreadKey := range dmThreadKeyMap {
		dmThreadKeyCopy := dmThreadKey
		dmThreadKeys = append(dmThreadKeys, &dmThreadKeyCopy)
	}

	return dmThreadKeys, nil
}

// GetPaginatedMessageEntriesForDmThread returns a list of paginated message entries for a given dm thread. The following
// constraints are applied:
// (1.) The startingTimestamp is the largest timestamp that we want to include in the results
// (2.) Fetch at most maxMessagesToFetch messages.
// (3.) _messageEntries are sorted by timestamp in descending order. That is, the most recent message is at index [0].
//
// In other words, the returned _messageEntries will follow these constraints:
// 1. _messageEntries[0].TimestampNanos <= startingMaxTimestamp
// 2. len(_messageEntries) <= maxMessagesToFetch
// 3. _messageEntries[i].TimestampNanos > _messageEntries[i+1].TimestampNanos
func (bav *UtxoView) GetPaginatedMessageEntriesForDmThread(dmThread DmThreadKey, startingTimestamp uint64,
	maxMessagesToFetch uint64) (_messageEntries []*NewMessageEntry, _err error) {

	return bav._getPaginatedMessageEntriesForDmThreadRecursionSafe(dmThread, startingTimestamp,
		maxMessagesToFetch, MaxDmMessageRecursionDepth)
}

// _getPaginatedMessageEntriesForDmThreadRecursionSafe is a helper function for GetPaginatedMessageEntriesForDmThread. It
// adds a recursion depth parameter to prevent infinite recursion. This paginated fetch will first fetch entries from the
// db and then combine them with the in-memory map of group chat message entries. If the in-memory map indicates that some
// db entries were deleted in this view, we might need to fetch more entries from the db to fill in the gaps.
// This is where we will make a recursive call to this function. The maxDepth parameter makes sure we don't recurse forever
// in case there is a bug in the code (though there isn't one).
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

	// Now that we have all the messages db and utxoView, we need to combine them and sort them by timestamp.
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

// setDmThreadIndex sets the DmThreadExistence index for a given DmThreadKey key, and DmThreadExistence entry.
func (bav *UtxoView) setDmThreadIndex(dmThreadKey DmThreadKey, existence DmThreadExistence) {
	existenceCopy := existence
	bav.DmThreadIndex[dmThreadKey] = &existenceCopy
}

// setDmThreadIndex deletes from the DmThreadExistence index for a given DmThreadKey.
func (bav *UtxoView) deleteDmThreadIndex(dmThreadKey DmThreadKey) {
	existence := MakeDmThreadExistence()
	existence.isDeleted = true
	bav.setDmThreadIndex(dmThreadKey, existence)
}

// ==================================================================
// NewMessage transaction connect/disconnect logic.
// ==================================================================

// _connectNewMessage is used to connect a NewMessage transaction to the UtxoView. Most common uses of this transaction
// include sending dm messages between two users, or group chat messages in a multi-party chat. The NewMessage transaction
// also allows for updating existing messages in both dm threads and group chat threads. Moreover, NewMessage transaction
// can be used to accept invitation requests to participate in a dm thread or group chat thread.
//
// Relationally, all messages sent via the NewMessage transaction are identified as a pair of two AccessGroupId's, along
// with an uint64 unix timestamp in nanoseconds TimestampNanos. The first AccessGroupId identifies the sender of the message,
// and the second AccessGroupId identifies the recipient of the message, i.e. we have the following basic index structure:
//
//	NewMessageEntry indexing:
//  	<SenderAccessGroupOwnerPublicKey, SenderAccessGroupKeyName,
//  	RecipientAccessGroupOwnerPublicKey, RecipientAccessGroupKeyName, TimestampNanos> -> NewMessageEntry
//
// Depending on the type of the thread, this message will be indexed in different ways. For example, if the thread is a
// dm thread, then we will store a single NewMessageEntry for each message sent, and two DmThreadExistence entries for
// each thread. The NewMessageEntry will be stored in the DmMessagesIndex index. The index deterministically orders the
// sender and recipient AccessGroupIds from the NewMessageEntry index by sorting them. And the DmThreadExistence entries
// allow for finding the sorted order of these AccessGroupIds. The idea is to first lookup the DmThreadExistence entry for
// the thread, and then order the AccessGroupIds to enumerate the NewMessageEntries, that we can for example sort by timestamp.
// With this in mind, we use the following index structure for dm messages:
// 	DmMessagesIndex:
//  	<MinorGroupOwnerPublicKey, MinorGroupKeyName,
// 		MajorGroupOwnerPublicKey, MajorGroupKeyName, TimestampNanos> -> NewMessageEntry
// 	DmThreadIndex:
//  	<UserGroupOwnerPublicKey, UserGroupKeyName,
//  	PartyUserGroupOwnerPublicKey, PartyUserGroupKeyName> -> DmThreadExistence
//
// The Minor, Major pair refers to a lexicographically smaller and greater byte encodings of the <AccessGroupOwnerPublicKey,
// AccessGroupKeyName> pair from (User, PartyUser) or (PartyUser, User).
//
// If the message type is a group chat message, then we will store a single NewMessageEntry for each message sent, and a
// single GroupChatThreadExistence entry for each group chat. The NewMessageEntry will be stored in the GroupChatMessagesIndex,
// and the DmThreadExistence entry will be stored in the GroupChatThreadIndex. Similarly to dm messages, the idea
// is to first lookup the GroupChatThreadExistence entry for the thread, and enumerate messages in the GroupChatMessagesIndex.
// We then use the following index structure for group chat messages:
// 	GroupChatMessagesIndex:
//  	<AccessGroupOwnerPublicKey, AccessGroupKeyName, TimestampNanos> -> NewMessageEntry
// 	GroupChatThreadIndex:
//  	<AccessGroupOwnerPublicKey, AccessGroupKeyName> -> GroupChatThreadExistence
//
// An interesting sub-problem arises from the choice of indexing messages by TimestampNanos, rather than by a logical index such as
// an incrementing counter. The question being, how do we prevent TimestampNanos spoofing? The answer is that we don't. We
// assume that the client will be responsible for setting the TimestampNanos to a reasonable value, and that the client
// will not attempt to spoof TimestampNanos. Transactions are always sequentially ordered in the blocks, so it's possible
// to detect whether some user is attempting to overwrite a message thread history by using old timestamps. Such behavior
// could potentially be "auto-banned" in larger group chats implementing fair use policy. If a user is attempting to
// send messages to appear in the future with larger TimestampNanos values than the current unix timestamp, then we're
// okay with that. Consider this to be a "deliver in the future" feature. The index structure of messages in both the
// dm and group chat threads allows for an efficient enumeration of messages up until the current unix timestamp,
// and the future messages can be discarded.
// TODO: Add info about the NewMessage transaction being used to accept invitations to dm threads and group chats.
func (bav *UtxoView) _connectNewMessage(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Make sure access groups are live.
	if blockHeight < bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		return 0, 0, nil, RuleErrorNewMessageBeforeDeSoAccessGroups
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNewMessage {
		return 0, 0, nil, fmt.Errorf("_connectNewMessage: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NewMessageMetadata)

	// Check the length of the EncryptedText, we don't allow messages to have more bytes than MaxNewMessageLengthBytes.
	if uint64(len(txMeta.EncryptedText)) > bav.Params.MaxNewMessageLengthBytes {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageEncryptedTextLengthExceedsMax, "_connectNewMessage: "+
				"EncryptedText length (%d) exceeds max length (%d)",
			len(txMeta.EncryptedText), bav.Params.MaxNewMessageLengthBytes)
	}

	// Verify that the sender of the message is the transactor. This constraint ensures authenticity of messages
	// sent via the NewMessage transaction. Basically, all NewMessageEntries stored will be certified sent by the
	// user specified as the message sender.
	// TODO: Do we want to allow group chat owners to update messages of group chat members? E.g. spam messages can be deleted.
	if !bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorNewMessageMessageSenderDoesNotMatchTxnPublicKey, "_connectNewMessage: "+
				"SenderAccessGroupOwnerPublicKey (%v) does not match txn.PublicKey (%v)",
			PkToString(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), bav.Params),
			PkToString(txn.PublicKey, bav.Params))
	}

	// Validate that no message has a zero timestamp.
	if txMeta.TimestampNanos == 0 {
		return 0, 0, nil, RuleErrorNewMessageTimestampNanosCannotBeZero
	}

	// Validate sender's access group id, verifying that the access group exists based on the UtxoView.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.SenderAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
			"SenderAccessGroupOwnerPublicKey and SenderAccessGroupKeyName are invalid")
	}

	// Validate recipient's access group id, verifying that the access group exists based on the UtxoView.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupKeyName.ToBytes(), blockHeight); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
			"RecipientAccessGroupOwnerPublicKey and RecipientAccessGroupKeyName are invalid")
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
			prevDmThreadExistence, err = bav._setUtxoViewMappingsForNewMessageOperationCreateTypeDm(txn, blockHeight, messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
					"Problem setting utxo view mappings for NewMessageOperationCreateTypeDm")
			}
		case NewMessageTypeGroupChat:
			prevGroupChatThreadExistence, err = bav._setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat(txn, blockHeight, messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
					"Problem setting utxo view mappings for NewMessageOperationCreateTypeGroupChat")
			}
		default:
			return 0, 0, nil, errors.Wrapf(
				RuleErrorNewMessageUnknownMessageType, "_connectNewMessage: unknown message type")
		}
	case NewMessageOperationUpdate:
		switch txMeta.NewMessageType {
		case NewMessageTypeDm:
			prevNewMessageEntry, prevDmThreadExistence, err = bav._setUtxoViewMappingsForNewMessageOperationUpdateTypeDm(txn, blockHeight, messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
					"Problem setting utxo view mappings for NewMessageOperationUpdateTypeDm")
			}
		case NewMessageTypeGroupChat:
			prevNewMessageEntry, prevGroupChatThreadExistence, err = bav._setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat(txn, blockHeight, messageEntry)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectNewMessage: "+
					"Problem setting utxo view mappings for NewMessageOperationUpdateTypeGroupChat")
			}
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

func (bav *UtxoView) _setUtxoViewMappingsForNewMessageOperationCreateTypeDm(
	txn *MsgDeSoTxn, blockHeight uint32, messageEntry *NewMessageEntry) (
	_prevDmThreadExistence *DmThreadExistence, _error error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNewMessage {
		return nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NewMessageMetadata)

	// Check that the message type is DM and operation create.
	if txMeta.NewMessageType != NewMessageTypeDm || txMeta.NewMessageOperation != NewMessageOperationCreate {
		return nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: "+
			"called with bad NewMessageType (%v) or bad NewMessageOperation (%v)",
			txMeta.NewMessageType, txMeta.NewMessageOperation)
	}

	var prevDmThreadExistence *DmThreadExistence
	if bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
		return nil, RuleErrorNewMessageDmSenderAndRecipientCannotBeTheSame
	}

	dmMessageKey := MakeDmMessageKeyForSenderRecipient(txMeta.SenderAccessGroupOwnerPublicKey, txMeta.SenderAccessGroupKeyName,
		txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

	dmMessage, err := bav.getDmMessagesIndex(dmMessageKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: Problem "+
			"getting dm message from index with dm message key %v: ", dmMessageKey)
	}
	if dmMessage != nil && !dmMessage.isDeleted {
		return nil, errors.Wrapf(RuleErrorNewMessageDmMessageAlreadyExists,
			"_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: DM thread already exists for sender (%v) and recipient (%v)",
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
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: Problem "+
			"making dm thread key from message entry: %v", messageEntry)
	}
	// Make a dm thread key for the sender.
	dmThreadKeyRecipient, err := MakeDmThreadKeyFromMessageEntry(messageEntry, true)
	if err != nil {
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: Problem "+
			"making dm thread key for sender from message entry: %v", messageEntry)
	}
	dmThread, err := bav.getDmThreadExistence(dmThreadKeySender)
	if err != nil {
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: Problem "+
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
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeDm: Problem "+
			"setting dm message in index with dm message key %v: ", dmMessageKey)
	}

	bav.setDmThreadIndex(dmThreadKeySender, MakeDmThreadExistence())
	bav.setDmThreadIndex(dmThreadKeyRecipient, MakeDmThreadExistence())

	return prevDmThreadExistence, nil
}

func (bav *UtxoView) _setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat(
	txn *MsgDeSoTxn, blockHeight uint32, messageEntry *NewMessageEntry) (
	_prevGroupChatThreadExistence *GroupChatThreadExistence, _error error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNewMessage {
		return nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NewMessageMetadata)

	// Check that the message type is group chat and operation create.
	if txMeta.NewMessageType != NewMessageTypeGroupChat || txMeta.NewMessageOperation != NewMessageOperationCreate {
		return nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: "+
			"called with bad NewMessageType (%v) or bad NewMessageOperation (%v)",
			txMeta.NewMessageType, txMeta.NewMessageOperation)
	}

	var prevGroupChatThreadExistence *GroupChatThreadExistence
	// Fetch the group chat entry, which is indexed by the recipient's access group.
	groupChatMessageKey := MakeGroupChatMessageKey(
		txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)
	groupChatMessage, err := bav.getGroupChatMessagesIndex(groupChatMessageKey)
	if err != nil {
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: Problem "+
			"getting group chat message from index with group chat message key %v: ", groupChatMessageKey)
	}
	if groupChatMessage != nil && !groupChatMessage.isDeleted {
		return nil, errors.Wrapf(RuleErrorNewMessageGroupChatMessageAlreadyExists,
			"_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: Group chat thread already exists for recipient (%v)",
			txMeta.RecipientAccessGroupOwnerPublicKey)
	}
	// We have previously verified the existence of access groups both for the sender and the recipient.
	// If the sender is not the owner of the group chat, we need to verify that they are a member of the group.
	if !bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
		groupMemberEntry, err := bav.GetAccessGroupMemberEntry(&txMeta.SenderAccessGroupOwnerPublicKey,
			&txMeta.RecipientAccessGroupOwnerPublicKey, &txMeta.RecipientAccessGroupKeyName)
		if err != nil {
			return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: Problem "+
				"getting group member entry for sender public key (%v) and recipient public key (%v) and recipient group name (%v)",
				txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName)
		}
		if groupMemberEntry == nil || groupMemberEntry.isDeleted {
			return nil, errors.Wrapf(RuleErrorNewMessageGroupChatMemberEntryDoesntExist,
				"_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: Sender (%v) is not a member of the group chat with ownerPublicKey (%v), groupKeyName (%v)",
				txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName)
		}
	}

	// Fetch the group chat thread existence entry, which is indexed by the recipient's access group.
	groupChatAccessGroupId := NewAccessGroupId(&txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName.ToBytes())
	// Sanity-check that the group chat thread we're reverting was properly set.
	groupChatThread, err := bav.getGroupChatThreadExistence(*groupChatAccessGroupId)
	if err != nil {
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: Problem "+
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
		return nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationCreateTypeGroupChat: Problem "+
			"setting group chat message in index with group chat message key %v: ", groupChatMessageKey)
	}
	bav.setGroupChatThreadIndex(*groupChatAccessGroupId, MakeGroupChatThreadExistence())

	return prevGroupChatThreadExistence, nil
}

func (bav *UtxoView) _setUtxoViewMappingsForNewMessageOperationUpdateTypeDm(
	txn *MsgDeSoTxn, blockHeight uint32, messageEntry *NewMessageEntry) (
	_prevNewMessageEntry *NewMessageEntry, _prevDmThreadExistence *DmThreadExistence, _error error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNewMessage {
		return nil, nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationUpdateTypeDm: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NewMessageMetadata)

	// Check that the message type is DM and operation update.
	if txMeta.NewMessageType != NewMessageTypeDm || txMeta.NewMessageOperation != NewMessageOperationUpdate {
		return nil, nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationUpdateTypeDm: "+
			"called with bad NewMessageType (%v) or bad NewMessageOperation (%v)",
			txMeta.NewMessageType, txMeta.NewMessageOperation)
	}

	var prevNewMessageEntry *NewMessageEntry
	var prevDmThreadExistence *DmThreadExistence

	if bytes.Equal(txMeta.SenderAccessGroupOwnerPublicKey.ToBytes(), txMeta.RecipientAccessGroupOwnerPublicKey.ToBytes()) {
		return nil, nil, RuleErrorNewMessageDmSenderAndRecipientCannotBeTheSame
	}

	dmMessageKey := MakeDmMessageKeyForSenderRecipient(txMeta.SenderAccessGroupOwnerPublicKey, txMeta.SenderAccessGroupKeyName,
		txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

	dmMessage, err := bav.getDmMessagesIndex(dmMessageKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationUpdateTypeDm: Problem "+
			"getting dm message from index with dm message key %v: ", dmMessageKey)
	}
	if dmMessage == nil || dmMessage.isDeleted {
		return nil, nil, errors.Wrapf(RuleErrorNewMessageDmMessageDoesNotExist,
			"_setUtxoViewMappingsForNewMessageOperationUpdateTypeDm: DM thread does not exist for sender (%v) and recipient (%v)",
			txMeta.SenderAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupOwnerPublicKey)
	}
	// Sanity-check that timestamps match.
	if dmMessage.TimestampNanos != txMeta.TimestampNanos {
		return nil, nil, errors.Wrapf(RuleErrorNewMessageDmMessageTimestampMismatch,
			"_setUtxoViewMappingsForNewMessageOperationUpdateTypeDm: DM thread timestamp (%v) does not match update timestamp (%v)",
			dmMessage.TimestampNanos, txMeta.TimestampNanos)
	}
	// Set the previous utxoView entry.
	copyDmMessage := *dmMessage
	prevNewMessageEntry = &copyDmMessage

	// Update the DM message entry.
	err = bav.setDmMessagesIndex(messageEntry)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationUpdateTypeDm: Problem "+
			"setting dm message in index with dm message key %v: ", dmMessageKey)
	}
	// Since a message exists, we know that the DM thread must also exist.
	// We should set the prevDmThreadExistence to exists for the UtxoOperation.
	dmThreadExists := MakeDmThreadExistence()
	prevDmThreadExistence = &dmThreadExists

	return prevNewMessageEntry, prevDmThreadExistence, nil
}

func (bav *UtxoView) _setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat(
	txn *MsgDeSoTxn, blockHeight uint32, messageEntry *NewMessageEntry) (
	_prevNewMessageEntry *NewMessageEntry, _prevGroupChatThreadExistence *GroupChatThreadExistence, _error error) {

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeNewMessage {
		return nil, nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*NewMessageMetadata)

	// Check that the message type is group chat and operation update.
	if txMeta.NewMessageType != NewMessageTypeGroupChat || txMeta.NewMessageOperation != NewMessageOperationUpdate {
		return nil, nil, fmt.Errorf("_setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat: "+
			"called with bad NewMessageType (%v) or bad NewMessageOperation (%v)",
			txMeta.NewMessageType, txMeta.NewMessageOperation)
	}

	var prevNewMessageEntry *NewMessageEntry
	var prevGroupChatThreadExistence *GroupChatThreadExistence

	// Fetch the group chat entry, which is indexed by the recipient's access group.
	groupChatMessageKey := MakeGroupChatMessageKey(
		txMeta.RecipientAccessGroupOwnerPublicKey, txMeta.RecipientAccessGroupKeyName, txMeta.TimestampNanos)

	groupChatMessage, err := bav.getGroupChatMessagesIndex(groupChatMessageKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat: Problem "+
			"getting group chat message from index with group chat message key %v: ", groupChatMessageKey)
	}
	if groupChatMessage == nil || groupChatMessage.isDeleted {
		return nil, nil, errors.Wrapf(RuleErrorNewMessageGroupChatMessageDoesNotExist,
			"_setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat: Group chat thread does not exist for recipient (%v)",
			txMeta.RecipientAccessGroupOwnerPublicKey)
	}
	// Sanity-check that timestamps match.
	if groupChatMessage.TimestampNanos != txMeta.TimestampNanos {
		return nil, nil, errors.Wrapf(RuleErrorNewMessageGroupMessageTimestampMismatch,
			"_setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat: Group chat thread timestamp (%v) does not match update timestamp (%v)",
			groupChatMessage.TimestampNanos, txMeta.TimestampNanos)
	}
	// Set the previous utxoView entry.
	copyGroupChatMessage := *groupChatMessage
	prevNewMessageEntry = &copyGroupChatMessage

	// Update the group chat message entry.
	err = bav.setGroupChatMessagesIndex(messageEntry)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "_setUtxoViewMappingsForNewMessageOperationUpdateTypeGroupChat: Problem "+
			"setting group chat message in index with group chat message key %v: ", groupChatMessageKey)
	}

	// Since a message exists, we know that the group chat thread must also exist.
	// We should set the prevGroupChatThreadExistence to exists for the UtxoOperation.
	groupChatThreadExists := MakeGroupChatThreadExistence()
	prevGroupChatThreadExistence = &groupChatThreadExists

	return prevNewMessageEntry, prevGroupChatThreadExistence, nil
}
