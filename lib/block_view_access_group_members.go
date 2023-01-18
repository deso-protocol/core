package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"sort"
)

// GetAccessGroupMemberEntry will check the membership index for membership of memberPublicKey in the group
// <groupOwnerPublicKey, groupKeyName>.
func (bav *UtxoView) GetAccessGroupMemberEntry(memberPublicKey *PublicKey, groupOwnerPublicKey *PublicKey,
	groupKeyName *GroupKeyName) (*AccessGroupMemberEntry, error) {

	// If either of the provided parameters is nil, we return.
	if memberPublicKey == nil || groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil, fmt.Errorf("GetAccessGroupMemberEntry: Called with nil memberPublicKey, groupOwnerPublicKey, or groupKeyName")
	}

	groupMembershipKey := NewGroupMembershipKey(*memberPublicKey, *groupOwnerPublicKey, *groupKeyName)

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	if mapValue, exists := bav.AccessGroupMembershipKeyToAccessGroupMember[*groupMembershipKey]; exists {
		return mapValue, nil
	}

	// If we get here, it means that the group has not been fetched in this utxoView. We fetch it from the db.
	dbAdapter := bav.GetDbAdapter()
	accessGroupMember, err := dbAdapter.GetAccessGroupMemberEntry(*memberPublicKey, *groupOwnerPublicKey, *groupKeyName)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupMemberEntry: Problem fetching access group member entry")
	}
	// If member exists in DB, we also set the mapping in utxoView.
	if accessGroupMember != nil {
		if err := bav._setAccessGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMember, groupOwnerPublicKey, groupKeyName); err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupMemberEntry: Problem setting group membership key to access group member mapping")
		}
	}
	return accessGroupMember, nil
}

// GetPaginatedAccessGroupMembersEnumerationEntries returns a list of public keys of members of a provided access group.
// The member public keys will be sorted lexicographically and paginated according to the provided startingAccessGroupMemberPublicKey
// and maxMembersToFetch. In other words, the returned _accessGroupMembers will follow these constraints:
//  1. len(_accessGroupMembers) <= maxMembersToFetch
//  2. _accessGroupMembers[0] > startingAccessGroupMemberPublicKey
//  3. \forall i, j: i < j => _accessGroupMembers[i] < _accessGroupMembers[j]
func (bav *UtxoView) GetPaginatedAccessGroupMembersEnumerationEntries(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	startingAccessGroupMemberPublicKey []byte, maxMembersToFetch uint32) (
	_accessGroupMembers []*PublicKey, _err error) {

	accessGroupMembers, _, err := bav._getPaginatedAccessGroupMembersEnumerationEntriesRecursionSafe(groupOwnerPublicKey, groupKeyName,
		startingAccessGroupMemberPublicKey, maxMembersToFetch, MaxAccessGroupMemberEnumerationRecursionDepth,
		nil, false)
	return accessGroupMembers, err
}

// _getPaginatedAccessGroupMembersEnumerationEntriesRecursionSafe is a helper function for GetPaginatedAccessGroupMembersEnumerationEntries.
// It adds a recursion depth counter to prevent infinite recursion, and it also adds an optional map accessGroupIdToSortedGroupMemberPublicKeysIter
// to keep track of which members have already been pre-fetched. The map must contain a sorted lists of members of the access group,
// beginning with the smallest (lexicographically) member in the db.
//
// This paginated fetch involves a bit more complexity than a generic "db -> utxoView" fetch; however, it gives the upside
// of an LRU cache that can be used to speed up paginated fetches. The downside is that it requires a bit more code to
// implement, and maintainability is probably lower. The accessGroupIdToSortedGroupMemberPublicKeysIter map can be left as nil.
func (bav *UtxoView) _getPaginatedAccessGroupMembersEnumerationEntriesRecursionSafe(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	startingAccessGroupMemberPublicKey []byte, maxMembersToFetch uint32, maxDepth uint32,
	accessGroupIdToSortedGroupMemberPublicKeysIter map[AccessGroupId][]*PublicKey, deepCopySortedMap bool) (
	_accessGroupMembers []*PublicKey, _accessGroupIdToSortedGroupMemberPublicKeys map[AccessGroupId][]*PublicKey, _err error) {

	// Deep-copy accessGroupIdToSortedGroupMemberPublicKeysIter so that we don't modify the original map.
	accessGroupIdToSortedGroupMemberPublicKeys := make(map[AccessGroupId][]*PublicKey)
	if deepCopySortedMap {
		for accessGroupIdIter, sortedGroupMemberPublicKeysIter := range accessGroupIdToSortedGroupMemberPublicKeysIter {
			accessGroupId := accessGroupIdIter
			var sortedGroupMemberPublicKeys []*PublicKey
			for _, sortedGroupMemberPublicKeyIter := range sortedGroupMemberPublicKeysIter {
				sortedGroupMemberPublicKey := *sortedGroupMemberPublicKeyIter
				sortedGroupMemberPublicKeys = append(sortedGroupMemberPublicKeys, &sortedGroupMemberPublicKey)
			}
			accessGroupIdToSortedGroupMemberPublicKeys[accessGroupId] = sortedGroupMemberPublicKeys
		}
	} else {
		if accessGroupIdToSortedGroupMemberPublicKeysIter != nil {
			accessGroupIdToSortedGroupMemberPublicKeys = accessGroupIdToSortedGroupMemberPublicKeysIter
		}
	}

	var cachedSortedAccessGroupMembersFromDb []*PublicKey
	if maxMembersToFetch == 0 {
		return cachedSortedAccessGroupMembersFromDb, accessGroupIdToSortedGroupMemberPublicKeys, nil
	}
	// This function can make recursive calls to itself. We use a depth counter to prevent infinite recursion
	// (which shouldn't happen anyway, but better safe than sorry, right?).
	if maxDepth == 0 {
		return nil, nil, errors.Wrapf(RuleErrorAccessGroupMemberEnumerationRecursionLimit,
			"_getPaginatedAccessGroupMembersEnumerationEntriesRecursionSafe: maxDepth == 0")
	}

	// If either of the provided parameters is nil, we return.
	if groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil, nil,
			fmt.Errorf("GetAccessGroupMembersEnumerationEntries: Called with nil groupOwnerPublicKey or groupKeyName")
	}

	accessGroupId := NewAccessGroupId(groupOwnerPublicKey, groupKeyName.ToBytes())

	// If the group membership map has already been fetched in this utxoView, then we get it directly from there.
	membersList, exists := accessGroupIdToSortedGroupMemberPublicKeys[*accessGroupId]

	// If there already is enough members in the UtxoView, we just go through them and return.
	// The UtxoView entries are sorted by memberPublicKey, so we can just go through them in order.
	// TODO: Use binary search/jump to iterate through members faster.
	if exists {
		for ii := 0; ii < len(membersList) && uint32(len(cachedSortedAccessGroupMembersFromDb)) < maxMembersToFetch; ii++ {
			accessGroupMemberPk := membersList[ii]
			// If the member public key is greater or equal lexicographically to the provided paginatedMemberPublicKey,
			// then we add it to the list of members to return.
			if bytes.Compare(accessGroupMemberPk.ToBytes(), startingAccessGroupMemberPublicKey) > 0 {
				cachedSortedAccessGroupMembersFromDb = append(cachedSortedAccessGroupMembersFromDb, accessGroupMemberPk)
			}
		}
	}

	paginationStartKey := startingAccessGroupMemberPublicKey
	if len(cachedSortedAccessGroupMembersFromDb) > 0 {
		paginationStartKey = cachedSortedAccessGroupMembersFromDb[len(cachedSortedAccessGroupMembersFromDb)-1].ToBytes()
	}

	// If we get here, it means that the group has not been fetched in this utxoView. We fetch it from the db.
	dbAdapter := bav.GetDbAdapter()
	accessGroupMembersFromDb, err := dbAdapter.GetPaginatedAccessGroupMembersEnumerationEntries(*groupOwnerPublicKey, *groupKeyName,
		paginationStartKey, maxMembersToFetch-uint32(len(cachedSortedAccessGroupMembersFromDb)))
	if err != nil {
		return nil, nil, errors.Wrapf(err,
			"GetAccessGroupMembersEnumerationEntries: Problem fetching access group members enumeration entries "+
				"for single member with accessGroupOwnerPublicKey: %v, accessGroupKeyName: %v, startingAccessGroupMemberPublicKey: %v",
			groupOwnerPublicKey, groupKeyName, startingAccessGroupMemberPublicKey)
	}
	//cachedSortedAccessGroupMembersFromDb = append(cachedSortedAccessGroupMembersFromDb, accessGroupMembersFromDb...)

	// We will now attempt to update the AccessGroupIdToSortedGroupMemberPublicKeys map in the UtxoView.
	// The map values have to be sorted lexicographically by memberPublicKey, so to maintain this invariant,
	// we will only augment map's values if the member public keys fetched from the DB are properly aligned.
	// There are two main cases to consider:
	// 	1) There is no mapping present for this group in the UtxoView.
	//  2) There already is a mapping present for this group in the UtxoView.

	if !exists {
		// 1)
		// We check what's the smallest lexicographic member public key for the group in the DB.
		firstMemberEntryFromDb, err := dbAdapter.GetPaginatedAccessGroupMembersEnumerationEntries(
			*groupOwnerPublicKey, *groupKeyName, []byte{}, 1)
		if err != nil {
			return nil, nil, errors.Wrapf(err,
				"GetAccessGroupMembersEnumerationEntries: Problem fetching access group members enumeration entries for "+
					"single member with accessGroupOwnerPublicKey: %v, accessGroupKeyName: %v, startingAccessGroupMemberPublicKey: %v",
				groupOwnerPublicKey, groupKeyName, startingAccessGroupMemberPublicKey)
		}
		// If the smallest lexicographic member public key is equal to the first member public key in the DB,
		// then we can safely set the mapping in the UtxoView to the entries fetched from the DB. Otherwise, we
		// do nothing since we fetched a section of all the members in the group that doesn't contain "the first"
		// member public key that should be present in the mapping.
		if len(firstMemberEntryFromDb) > 0 && len(accessGroupMembersFromDb) > 0 &&
			bytes.Equal(firstMemberEntryFromDb[0].ToBytes(), accessGroupMembersFromDb[0].ToBytes()) {

			if accessGroupIdToSortedGroupMemberPublicKeys, err = _setAccessGroupIdToSortedGroupMemberPublicKeys(*groupOwnerPublicKey, *groupKeyName,
				accessGroupMembersFromDb, accessGroupIdToSortedGroupMemberPublicKeys); err != nil {
				return nil, nil, errors.Wrapf(err,
					"GetAccessGroupMembersEnumerationEntries: Problem setting access group members enumeration "+
						"entries for single member with accessGroupOwnerPublicKey: %v, accessGroupKeyName: %v, startingAccessGroupMemberPublicKey: %v",
					groupOwnerPublicKey, groupKeyName, startingAccessGroupMemberPublicKey)
			}
		}
	} else {
		// 2)
		// We need to check that the db entries extend the current sorted member public keys present in the UtxoView.
		// This would happen if the number of cachedSortedAccessGroupMembersFromDb filtered from the UtxoView is less than the number of
		// maxMembersToFetch. In this case, we needed more member public keys, and we resorted to fetching them from the DB,
		// meaning these public keys naturally lexicographically extend the member public keys already present in the UtxoView.

		// TODO: Can we use some bigger brain ordered structure to always add db entries to the UtxoView?
		if len(cachedSortedAccessGroupMembersFromDb) > 0 && len(accessGroupMembersFromDb) > 0 {
			// We now extend the mapping in the UtxoView with the entries fetched from the DB.
			newSortedGroupMemberPublicKeys := append(membersList, accessGroupMembersFromDb...)
			if accessGroupIdToSortedGroupMemberPublicKeys, err = _setAccessGroupIdToSortedGroupMemberPublicKeys(
				*groupOwnerPublicKey, *groupKeyName, newSortedGroupMemberPublicKeys, accessGroupIdToSortedGroupMemberPublicKeys); err != nil {
				return nil, nil, errors.Wrapf(err,
					"GetAccessGroupMembersEnumerationEntries: Problem setting access group members enumeration "+
						"entries for single member with accessGroupOwnerPublicKey: %v, accessGroupKeyName: %v, startingAccessGroupMemberPublicKey: %v",
					groupOwnerPublicKey, groupKeyName, startingAccessGroupMemberPublicKey)
			}
		}
	}
	cachedSortedAccessGroupMembersFromDb = append(cachedSortedAccessGroupMembersFromDb, accessGroupMembersFromDb...)
	// We define a predicate that checks whether we fetched maximum number of members. We might drop some entries later
	// when we combine the db member public keys with the ones fetched from the UtxoView.
	isListFilled := uint32(len(cachedSortedAccessGroupMembersFromDb)) == maxMembersToFetch
	var lastKnownDbPublicKey []byte
	if len(cachedSortedAccessGroupMembersFromDb) > 0 {
		lastKnownDbPublicKey = cachedSortedAccessGroupMembersFromDb[len(cachedSortedAccessGroupMembersFromDb)-1].ToBytes()
	}

	// Finally, there is a possibility that there have been new members added to the access group in the current block,
	// and we need to make sure we include them in the list of members we return. We do this by iterating over all the
	// members in the current UtxoView and inserting them into the list of members we return.
	existingAccessMembers := make(map[PublicKey]struct{})
	for _, member := range cachedSortedAccessGroupMembersFromDb {
		existingAccessMembers[*member] = struct{}{}
	}
	filteredUtxoViewMembers := make(map[PublicKey]*AccessGroupMemberEntry)
	for membershipKey, memberEntry := range bav.AccessGroupMembershipKeyToAccessGroupMember {
		// If member entry doesn't match our access group, we skip it.
		isAccessGroupMember := bytes.Equal(membershipKey.AccessGroupOwnerPublicKey.ToBytes(), groupOwnerPublicKey.ToBytes()) &&
			bytes.Equal(membershipKey.AccessGroupKeyName.ToBytes(), groupKeyName.ToBytes())
		if !isAccessGroupMember {
			continue
		}

		// Make sure that the member public key is greater than our pagination starting key.
		memberPublicKey := membershipKey.AccessGroupMemberPublicKey
		isGreaterThanStartKey := bytes.Compare(memberPublicKey.ToBytes(), startingAccessGroupMemberPublicKey) > 0
		if !isGreaterThanStartKey {
			continue
		}

		// In case we already fetched the maximum number of members, we just need to check whether the current member
		// is smaller or equal to the last member we fetched from the DB. If it isn't, we can skip. The reason is that
		// if we added the member with greater public key, there is a chance there might be some members with smaller
		// public key still present in the db, which we shouldn't skip.
		var isLesserOrEqualThanEndKey bool
		if len(cachedSortedAccessGroupMembersFromDb) > 0 {
			// Note we use <= here because if the UtxoView entry is deleted, we should remove the member from our list.
			isLesserOrEqualThanEndKey = bytes.Compare(memberPublicKey.ToBytes(), lastKnownDbPublicKey) <= 0
		} else {
			isLesserOrEqualThanEndKey = true
		}

		// If we already fetched the maximum number of members, we will just check whether the UtxoView member is within
		// the range of the members we fetched from the DB. If it isn't then we can discard this member for now, as
		// we might later add them in a recursive call to fetch more paginated members.
		if !isLesserOrEqualThanEndKey && isListFilled {
			continue
		}

		// This is a valid member that we need to add to our list of members. We add him to our filtered utxoView entry map.
		memberEntryCopy := *memberEntry
		filteredUtxoViewMembers[*memberEntryCopy.AccessGroupMemberPublicKey] = &memberEntryCopy
	}

	finalMemberPublicKeys := []*PublicKey{}
	for existingMemberPk := range existingAccessMembers {
		if utxoMember, exists := filteredUtxoViewMembers[existingMemberPk]; exists {
			if utxoMember.isDeleted {
				continue
			}
		}
		copyExistingMemberPk := existingMemberPk
		finalMemberPublicKeys = append(finalMemberPublicKeys, &copyExistingMemberPk)
	}
	for utxoMemberPk, utxoMember := range filteredUtxoViewMembers {
		if _, exists := existingAccessMembers[utxoMemberPk]; exists {
			continue
		}
		if utxoMember.isDeleted {
			continue
		}
		copyUtxoMemberPk := utxoMemberPk
		finalMemberPublicKeys = append(finalMemberPublicKeys, &copyUtxoMemberPk)
	}
	sort.Slice(finalMemberPublicKeys, func(ii, jj int) bool {
		return bytes.Compare(finalMemberPublicKeys[ii].ToBytes(), finalMemberPublicKeys[jj].ToBytes()) < 0
	})

	// After iterating over all the members in the current UtxoView, there is a possibility that we now have less members
	// than the maxMembersToFetch, due to deleted members. In this case, we need to fetch more members from the DB,
	// which we will do with the magic of recursion.
	if isListFilled && len(finalMemberPublicKeys) < int(maxMembersToFetch) &&
		bytes.Compare(startingAccessGroupMemberPublicKey, lastKnownDbPublicKey) < 0 {
		// Note this recursive call will never lead to an infinite loop because the startingAccessGroupMemberPublicKey
		// will be growing with each recursive call, and because we are checking for isListFilled with
		// maxMembersToFetch > 0. But just in case we add a sanity-check parameter maxDepth to break long recursive calls.
		remainingMembers, newAccessGroupIdToSortedGroupMemberPublicKeys, err := bav._getPaginatedAccessGroupMembersEnumerationEntriesRecursionSafe(
			groupOwnerPublicKey, groupKeyName, lastKnownDbPublicKey, maxMembersToFetch-uint32(len(finalMemberPublicKeys)),
			maxDepth-1, accessGroupIdToSortedGroupMemberPublicKeys, false)
		if err != nil {
			return nil, nil, err
		}
		finalMemberPublicKeys = append(finalMemberPublicKeys, remainingMembers...)
		accessGroupIdToSortedGroupMemberPublicKeys = newAccessGroupIdToSortedGroupMemberPublicKeys
	}

	if len(finalMemberPublicKeys) > int(maxMembersToFetch) {
		finalMemberPublicKeys = finalMemberPublicKeys[:maxMembersToFetch]
	}
	return finalMemberPublicKeys, accessGroupIdToSortedGroupMemberPublicKeys, nil
}

func _setAccessGroupIdToSortedGroupMemberPublicKeys(accessGroupOwnerPublicKey PublicKey, accessGroupKeyName GroupKeyName,
	accessGroupMemberPublicKeys []*PublicKey, accessGroupIdToSortedGroupMemberPublicKeys map[AccessGroupId][]*PublicKey) (
	_accessGroupIdToSortedGroupMemberPublicKeys map[AccessGroupId][]*PublicKey, _err error) {

	// Sanity-check that we're not setting any duplicate public keys in the accessGroupMemberPublicKeys array.
	membersMap := make(map[PublicKey]struct{})
	for _, accessGroupMemberPublicKey := range accessGroupMemberPublicKeys {
		if _, exists := membersMap[*accessGroupMemberPublicKey]; exists {
			return accessGroupIdToSortedGroupMemberPublicKeys, fmt.Errorf("_setAccessGroupIdToSortedGroupMemberPublicKeys: " +
				"accessGroupMemberPublicKeys contains duplicate entries")
		}
	}

	// Create access group id.
	accessGroupId := AccessGroupId{
		AccessGroupOwnerPublicKey: accessGroupOwnerPublicKey,
		AccessGroupKeyName:        accessGroupKeyName,
	}
	// Set the mapping.
	accessGroupIdToSortedGroupMemberPublicKeys[accessGroupId] = accessGroupMemberPublicKeys
	return accessGroupIdToSortedGroupMemberPublicKeys, nil
}

// _setAccessGroupMembershipKeyToAccessGroupMemberMapping sets the mapping for the provided accessGroupMemberEntry in
// the access group identified by the accessGroupId of <accessGroupOwnerPublicKey, accessGroupKeyName>.
func (bav *UtxoView) _setAccessGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMemberEntry *AccessGroupMemberEntry,
	accessGroupOwnerPublicKey *PublicKey, accessGroupKeyName *GroupKeyName) error {

	// This function shouldn't be called with a nil member.
	if accessGroupMemberEntry == nil || accessGroupOwnerPublicKey == nil || accessGroupKeyName == nil {
		return fmt.Errorf("_setAccessGroupMembershipKeyToAccessGroupMemberMapping: " +
			"Called with nil accessGroupMemberEntry, accessGroupOwnerPublicKey, or accessGroupKeyName")
	}

	// Create group membership key.
	groupMembershipKey := *NewGroupMembershipKey(
		*accessGroupMemberEntry.AccessGroupMemberPublicKey, *accessGroupOwnerPublicKey, *accessGroupKeyName)
	// Set the mapping.
	bav.AccessGroupMembershipKeyToAccessGroupMember[groupMembershipKey] = accessGroupMemberEntry
	return nil
}

// _deleteAccessGroupMembershipKeyToAccessGroupMemberMapping will delete the membership mapping for the provided
// accessGroupMemberEntry in the access group identified by the accessGroupId of <accessGroupOwnerPublicKey, accessGroupKeyName>.
func (bav *UtxoView) _deleteAccessGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMemberEntry *AccessGroupMemberEntry,
	accessGroupOwnerPublicKey *PublicKey, accessGroupKeyName *GroupKeyName, blockHeight uint64) error {

	// This function shouldn't be called with a nil member.
	if accessGroupMemberEntry == nil || accessGroupMemberEntry.AccessGroupMemberPublicKey == nil ||
		accessGroupOwnerPublicKey == nil || accessGroupKeyName == nil {
		return fmt.Errorf("_deleteAccessGroupMembershipKeyToAccessGroupMemberMapping: Called with nil accessGroupMemberEntry, " +
			"accessGroupMemberEntry.AccessGroupMemberPublicKey, accessGroupOwnerPublicKey, or accessGroupKeyName")
	}

	// Create a tombstone entry.
	// Clone the existing entry so that we can set prevAccessGroupEntry for utxoOps.
	tombstoneAccessGroupMember := *accessGroupMemberEntry
	tombstoneAccessGroupMember.isDeleted = true

	// set utxoView mapping
	if err := bav._setAccessGroupMembershipKeyToAccessGroupMemberMapping(&tombstoneAccessGroupMember, accessGroupOwnerPublicKey, accessGroupKeyName); err != nil {
		return errors.Wrapf(err, "_deleteAccessGroupMembershipKeyToAccessGroupMemberMapping: Problem setting group membership key to access group member mapping")
	}
	return nil
}

// _connectAccessGroupMembers is used to connect an AccessGroupMembers transaction to the UtxoView. This transaction
// is used to update members of an existing access group that was previously created via AccessGroup transaction.
// Member updates comprise operations such as adding a new member, removing an existing member, or modifying an existing
// member's entry.
//
// Access group members are identified by a tuple of:
//
//	<AccessGroupOwnerPublicKey, AccessGroupKeyName, AccessGroupMemberPublicKey, AccessGroupMemberKeyName>
//
// It is worth noting that access group members are added to access groups via their own access groups. You can see by
// looking at the index, that it is essentially a 2-access group relationship between the owner's access group and
// member's access group.
func (bav *UtxoView) _connectAccessGroupMembers(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Make sure access groups are live.
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupMembersBeforeBlockHeight, "_connectAccessGroupMembers: "+
				"Problem connecting access group members: DeSo V3 messages are not live yet")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAccessGroupMembers {
		return 0, 0, nil, fmt.Errorf("_connectAccessGroupMembers: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	// Now we know txn.TxnMeta is AccessGroupMembersMetadata
	txMeta := txn.TxnMeta.(*AccessGroupMembersMetadata)

	// We only accept member transactions from group owners. Permissions on access groups can be done via derived keys
	// and spending limits. For on-chain permissions, you can have an API standard for access groups storing
	// derived keys that are shared with the right users that were given permissions.
	if !bytes.Equal(txn.PublicKey, txMeta.AccessGroupOwnerPublicKey) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupMemberPublicKeyCannotBeDifferent, "_connectAccessGroupMembers: Problem connecting "+
				"access group members: access group owner public key and transaction public key cannot be different")
	}

	// If the key name is just a list of 0s, then return because this name is reserved for the base key, which has no members.
	if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), BaseGroupKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupsNameCannotBeZeros, "_connectAccessGroupMembers: "+
				"Problem connecting access group members: Cannot add members to base key.")
	}

	// Make sure the access group members list is not empty.
	if len(txMeta.AccessGroupMembersList) == 0 {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupMembersListCannotBeEmpty, "_connectAccessGroupMembers: Problem connecting access "+
				"group members: Access group member list is empty for txnMeta (%v).", txMeta)
	}

	// Make sure that the access group to which we want to add members exists.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName, blockHeight); err != nil {

		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupDoesntExist, "_connectAccessGroupMembers: Problem connecting access group "+
				"members: Access group does not exist for txnMeta (%v). Error: %v", txMeta, err)
	}

	// Connect basic txn to get the total input and the total output without considering the transaction metadata.
	// Note that it doesn't matter when we do this, because if the transaction fails later on, we will just revert the
	// UtxoView to a previous stable state that isn't corrupted with partial block view entries.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: ")
	}

	// Make sure there are no duplicate members with the same AccessGroupMemberPublicKey in the transaction's metadata.
	accessGroupMemberPublicKeys := make(map[PublicKey]struct{})
	for _, accessMember := range txMeta.AccessGroupMembersList {
		// If the group owner decides to add themselves as a member, there is an edge-case where the owner would
		// add themselves as a member by the same group -- which would create a possible recursion. We prevent this
		// situation with the below validation check.
		if bytes.Equal(txMeta.AccessGroupOwnerPublicKey, accessMember.AccessGroupMemberPublicKey) &&
			bytes.Equal(NewGroupKeyName(txMeta.AccessGroupKeyName).ToBytes(), NewGroupKeyName(accessMember.AccessGroupMemberKeyName).ToBytes()) {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupMemberCantAddOwnerBySameGroup,
				"_disconnectAccessGroupMembers: Can't add the owner of the group as a member of the group using the same group key name.")
		}
		if err := ValidateAccessGroupPublicKeyAndName(accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: Problem validating access group member "+
				"public key and name for access member (%v)", accessMember)
		}
		memberPublicKey := *NewPublicKey(accessMember.AccessGroupMemberPublicKey)
		if _, exists := accessGroupMemberPublicKeys[memberPublicKey]; exists {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorAccessGroupMemberListDuplicateMember, "_connectAccessGroupMembers: "+
					"Problem connecting access group members: Access group member with public key (%v) "+
					"appears more than once in the AccessGroupMemberList.", memberPublicKey)
		}
		accessGroupMemberPublicKeys[memberPublicKey] = struct{}{}
	}

	// We also validate that each access group member entry in transaction metadata points to an existing,
	// previously registered access group.
	for _, accessMember := range txMeta.AccessGroupMembersList {
		if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
			accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName, blockHeight); err != nil {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupDoesntExist, "_connectAccessGroupMembers: "+
				"Problem validating access group for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v, error: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName, err)
		}
	}

	// Some operations might modify existing access group members, so we need to keep track of the previous entries for UtxoOps.
	var prevAccessGroupMemberEntries []*AccessGroupMemberEntry

	// Determine the operation that we want to perform on the access group members.
	switch txMeta.AccessGroupMemberOperationType {
	case AccessGroupMemberOperationTypeAdd:
		if err := bav._setUtxoViewMappingsForAccessGroupMemberOperationAdd(txMeta, uint64(blockHeight)); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: Problem adding access group members.")
		}

	case AccessGroupMemberOperationTypeRemove:
		if prevAccessGroupMemberEntries, err = bav._setUtxoViewMappingsForAccessGroupMemberOperationRemove(txMeta, uint64(blockHeight)); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: Problem removing access group members.")
		}

	case AccessGroupMemberOperationTypeUpdate:
		if prevAccessGroupMemberEntries, err = bav._setUtxoViewMappingsForAccessGroupMemberOperationUpdate(txMeta, uint64(blockHeight)); err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: Problem updating access group members.")
		}

	default:
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupMemberOperationTypeNotSupported, "_connectAccessGroupMembers: "+
				"Operation type %v not supported.", txMeta.AccessGroupMemberOperationType)
	}

	// Sanity-check that the prevAccessGroupMember entries have been properly set.
	if err := bav.validatePrevAccessGroupMemberEntries(txMeta, prevAccessGroupMemberEntries); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: ")
	}
	// utxoOpsForTxn is an array of UtxoOperations. We append to it below to record the UtxoOperations
	// associated with this transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                       OperationTypeAccessGroupMembers,
		PrevAccessGroupMembersList: prevAccessGroupMemberEntries,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// _disconnectAccessGroupMembers is the inverse of _connectAccessGroupMembers. It is used to disconnect an AccessGroupMembers
// transaction from the UtxoView.
func (bav *UtxoView) _disconnectAccessGroupMembers(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last UtxoOperation is an AccessGroupMembersOperation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAccessGroupMembers: Trying to revert " +
			"AccessGroupMembersList but with no operations")
	}
	accessGroupMembersOp := utxoOpsForTxn[len(utxoOpsForTxn)-1]
	if accessGroupMembersOp.Type != OperationTypeAccessGroupMembers {
		return fmt.Errorf("_disconnectAccessGroupMembers: Trying to revert "+
			"AccessGroupMembersList but found types %v and %v", accessGroupMembersOp.Type, operationType)
	}

	// Check that the transaction has the right TxnType.
	if currentTxn.TxnMeta.GetTxnType() != TxnTypeAccessGroupMembers {
		return fmt.Errorf("_disconnectAccessGroupMembers: called with bad TxnType %s",
			currentTxn.TxnMeta.GetTxnType().String())
	}

	// Get the transaction metadata.
	txMeta := currentTxn.TxnMeta.(*AccessGroupMembersMetadata)

	// Sanity check that the access public key and key name are valid.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName, blockHeight); err != nil {
		return errors.Wrapf(RuleErrorAccessGroupDoesntExist, "_disconnectAccessGroupMembers: "+
			"Problem validating access public key or group key name for txnMeta (%v): error: %v", txMeta, err)
	}

	// Make sure the access group member public key and key name are valid and that they point to an existing
	// access group.
	for _, accessMember := range txMeta.AccessGroupMembersList {
		if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
			accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName, blockHeight); err != nil {
			return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
				"Problem validating public key or access key for member with "+
				"(AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
	}

	// Loop over members to make sure they are the same.
	switch txMeta.AccessGroupMemberOperationType {
	case AccessGroupMemberOperationTypeAdd:
		// We will iterate over all members in the transaction's metadata and delete each one. Since the result of the
		// AccessGroupMemberOperationTypeAdd is that a new member is added to the access group, we can just delete the
		// members from the metadata, since a member could have only been added if he hasn't existed before.
		for _, accessMember := range txMeta.AccessGroupMembersList {
			// Now fetch the access group member entry and verify that it exists.
			memberGroupEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
				NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
			if err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: disconnect add "+
					"problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}
			// If the access group member was already deleted, we error because something went wrong.
			if memberGroupEntry == nil || memberGroupEntry.isDeleted {
				return errors.Wrapf(
					RuleErrorAccessMemberDoesntExist, "_disconnectAccessGroupMembers: disconnect add member doesn't exist "+
						"for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}

			// Delete the access group member from the UtxoView.
			if err := bav._deleteAccessGroupMembershipKeyToAccessGroupMemberMapping(memberGroupEntry, NewPublicKey(txMeta.AccessGroupOwnerPublicKey),
				NewGroupKeyName(txMeta.AccessGroupKeyName), uint64(blockHeight)); err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: disconnect add "+
					"problem deleting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					memberGroupEntry.AccessGroupMemberPublicKey, memberGroupEntry.AccessGroupMemberKeyName)
			}
		}

	case AccessGroupMemberOperationTypeRemove:
		// Sanity-check that all information about access group members in txMeta is correct.
		for _, accessMember := range txMeta.AccessGroupMembersList {
			// sanity-check that the EncryptedKey is left empty for all the removed members.
			if len(accessMember.EncryptedKey) != 0 {
				return errors.Wrapf(RuleErrorAccessGroupMemberRemoveEncryptedKeyNotEmpty,
					"_disconnectAccessGroupMembers: disconnect remove encrypted key should be empty for OperationTypeRemove, "+
						"but received (EncryptedKey=%v) for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.EncryptedKey, accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}
			if len(accessMember.ExtraData) != 0 {
				return errors.Wrapf(RuleErrorAccessGroupMemberRemoveExtraDataNotEmpty,
					"_disconnectAccessGroupMembers: disconnect remove ExtraData should be empty for OperationTypeRemove, "+
						"but received (ExtraData=%v) for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.ExtraData, accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}

			// Fetch the access group member entry for each member from the transaction metadata.
			memberGroupEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
				NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
			if err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
					"disconnect remove problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}

			// We expect that the member entry we are trying to revert-remove has been deleted from the UtxoView.
			// By inverse, we will error if the entry exists and isn't deleted.
			if memberGroupEntry != nil && !memberGroupEntry.isDeleted {
				return errors.Wrapf(RuleErrorAccessMemberAlreadyExists, "_disconnectAccessGroupMembers: "+
					"disconnect remove member already exists for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}
		}
		// Sanity-check that the size of the prevAccessGroupMembers is the same as the txMeta access group members.
		if len(accessGroupMembersOp.PrevAccessGroupMembersList) != len(txMeta.AccessGroupMembersList) {
			return errors.Wrapf(RuleErrorAccessGroupPrevMembersListIsIncorrect, "_disconnectAccessGroupMembers: "+
				"disconnect remove failed sanity-check on length of prevAccessGroupMemberPublicKeys, was expecting (len=%v) but got (len=%v)",
				len(txMeta.AccessGroupMembersList), len(accessGroupMembersOp.PrevAccessGroupMembersList))
		}
		// Now that we've validated everything, we can revert to previous access group member entries.
		for _, prevAccessMember := range accessGroupMembersOp.PrevAccessGroupMembersList {
			copyPrevAccessMember := *prevAccessMember
			if err := bav._setAccessGroupMembershipKeyToAccessGroupMemberMapping(&copyPrevAccessMember, NewPublicKey(txMeta.AccessGroupOwnerPublicKey),
				NewGroupKeyName(txMeta.AccessGroupKeyName)); err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: disconnect remove problem reverting to previous access group member "+
					"entry for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					prevAccessMember.AccessGroupMemberPublicKey, prevAccessMember.AccessGroupMemberKeyName)
			}
		}
	case AccessGroupMemberOperationTypeUpdate:
		// Sanity-check that the size of the prevAccessGroupMembers is the same as the txMeta access group members.
		if len(accessGroupMembersOp.PrevAccessGroupMembersList) != len(txMeta.AccessGroupMembersList) {
			return errors.Wrapf(RuleErrorAccessGroupPrevMembersListIsIncorrect, "_disconnectAccessGroupMembers: "+
				"disconnect update failed sanity-check on length of prevAccessGroupMemberPublicKeys, was expecting (len=%v) but got (len=%v)",
				len(txMeta.AccessGroupMembersList), len(accessGroupMembersOp.PrevAccessGroupMembersList))
		}
		// Sanity-check that all information about access group members in txMeta is correct.
		for _, accessMember := range txMeta.AccessGroupMembersList {
			memberGroupEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
				NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
			if err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
					"disconnect update problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}

			// We expect that the member entry we are trying to revert-update exists in the UtxoView.
			if memberGroupEntry == nil || memberGroupEntry.isDeleted {
				return errors.Wrapf(RuleErrorAccessMemberDoesntExist, "_disconnectAccessGroupMembers: "+
					"disconnect update member does not exist for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
			}
		}
		// Now that we've validated everything, we can revert to previous access group member entries.
		for _, prevAccessMember := range accessGroupMembersOp.PrevAccessGroupMembersList {
			copyPrevAccessMember := *prevAccessMember
			if err := bav._setAccessGroupMembershipKeyToAccessGroupMemberMapping(&copyPrevAccessMember, NewPublicKey(txMeta.AccessGroupOwnerPublicKey),
				NewGroupKeyName(txMeta.AccessGroupKeyName)); err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: disconnect update problem reverting to previous access group member "+
					"entry for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					prevAccessMember.AccessGroupMemberPublicKey, prevAccessMember.AccessGroupMemberKeyName)
			}
		}
	default:
		return errors.Wrapf(RuleErrorAccessGroupMemberOperationTypeNotSupported, "_connectAccessGroup: "+
			"Operation type %v not supported.", txMeta.AccessGroupMemberOperationType)
	}

	// Now disconnect the basic transfer.
	operationIndex := len(utxoOpsForTxn) - 1
	return bav._disconnectBasicTransfer(currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}

func (bav *UtxoView) _setUtxoViewMappingsForAccessGroupMemberOperationAdd(txMeta *AccessGroupMembersMetadata,
	blockHeight uint64) error {

	// Sanity-check that all information about access group members in txMeta is correct.
	if txMeta.AccessGroupMemberOperationType != AccessGroupMemberOperationTypeAdd {
		return errors.Wrapf(RuleErrorAccessGroupMemberOperationTypeNotSupported, "_setUtxoViewMappingsForAccessGroupMemberOperationAdd: "+
			"Operation type %v not supported.", txMeta.AccessGroupMemberOperationType)
	}

	// AccessGroupMemberOperationTypeAdd indicates that we want to add members to the access group.
	// Members are added to the access group by their own existing access groups, identified by the pair of:
	// 	<AccessGroupMemberPublicKey, AccessGroupMemberKeyName>
	// Aside from the member's public key and group key name, access group member entries contain
	// a field called EncryptedKey, which stores the main group's access public key encrypted to the member
	// group's access public key. This is used to allow the member to decrypt the main group's access public key
	// using their individual access groups' secrets.
	for _, accessMember := range txMeta.AccessGroupMembersList {
		// We allow a situation, where the group owner adds themselves as a member of their own group. This behavior
		// is recommended for all groups, to allow having a single master access group that can be used to decrypt
		// all the other access groups. The suggested approach is to select an access group with group key name of
		// "default-key" (encoded as utf-8 bytes).
		//
		// We have previously validated that the accessMember public key and access key name are valid, and point to
		// an existing access group. We should now validate that the access member hasn't already been added
		// to this group in the past.
		memberGroupEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
			NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
		if err != nil {
			return errors.Wrapf(err, "_setUtxoViewMappingsForAccessGroupMemberOperationAdd: "+
				"Problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
		// If the access group member already exists, and wasn't deleted, we error because we can't add the same member twice.
		if memberGroupEntry != nil && !memberGroupEntry.isDeleted {
			return errors.Wrapf(
				RuleErrorAccessMemberAlreadyExists, "_setUtxoViewMappingsForAccessGroupMemberOperationAdd: member already exists "+
					"for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}

		// Since this new access group member passed all the validation steps, we can add the AccessGroupMemberEntry
		// to the UtxoView. Note that it doesn't matter when we do this, because if the transaction fails later on,
		// we will revert UtxoView to the backup view.
		accessGroupMemberEntry := &AccessGroupMemberEntry{
			AccessGroupMemberPublicKey: NewPublicKey(accessMember.AccessGroupMemberPublicKey),
			AccessGroupMemberKeyName:   NewGroupKeyName(accessMember.AccessGroupMemberKeyName),
			EncryptedKey:               accessMember.EncryptedKey,
			ExtraData:                  accessMember.ExtraData,
		}

		if err := bav._setAccessGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMemberEntry,
			NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName)); err != nil {
			return errors.Wrapf(err, "_setUtxoViewMappingsForAccessGroupMemberOperationAdd: "+
				"Problem setting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
	}
	return nil
}

func (bav *UtxoView) _setUtxoViewMappingsForAccessGroupMemberOperationRemove(txMeta *AccessGroupMembersMetadata,
	blockHeight uint64) (_prevAccessGroupMemberEntries []*AccessGroupMemberEntry, _err error) {

	// Sanity-check that the operation type is correct.
	if txMeta.AccessGroupMemberOperationType != AccessGroupMemberOperationTypeRemove {
		return nil, errors.Wrapf(RuleErrorAccessGroupMemberOperationTypeNotSupported,
			"_setUtxoViewMappingsForAccessGroupMemberOperationRemove: "+
				"OperationType should be AccessGroupMemberOperationTypeRemove, but received (OperationType=%v)",
			txMeta.AccessGroupMemberOperationType)
	}

	// AccessGroupMemberOperationTypeRemove operation is used to remove members from an access group. The result of
	// this operation is that all the members specified in the transaction's metadata will be purged from the DB as
	// if they were never added to the access group in the first place. It's worth noting, that this "removal" of
	// access group members is not theoretically correct because we will maintain the same
	// AccessGroupPublicKey/PrivateKey for the access group, meaning that the access group member still has
	// the knowledge of this keypair (including the secret), provided they have persisted this information off-chain.
	// We can't force removed access group members to "unsee" the access group secret. There is a remedy to this,
	// although it involves slightly more complexity. Essentially, to properly remove members from the access group,
	// we would need to rotate the group's secret to a different key and treat it as the new secret. Like I mentioned,
	// this involves a bit more complexity, especially to do efficiently. As such, we refrain from implementing this
	// solution yet, and a new operation will be added in the future if needed.
	var prevAccessGroupMemberEntries []*AccessGroupMemberEntry

	for _, accessMember := range txMeta.AccessGroupMembersList {
		// Because we're just removing members, the EncryptedKey field for each member should be left empty.
		// If it isn't, we'll throw a RuleError.
		if len(accessMember.EncryptedKey) != 0 {
			return nil, errors.Wrapf(RuleErrorAccessGroupMemberRemoveEncryptedKeyNotEmpty,
				"_setUtxoViewMappingsForAccessGroupMemberOperationRemove: Encrypted key should be empty for OperationTypeRemove, but received (EncryptedKey=%v) for "+
					"member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.EncryptedKey, accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
		if len(accessMember.ExtraData) != 0 {
			return nil, errors.Wrapf(RuleErrorAccessGroupMemberRemoveExtraDataNotEmpty,
				"_setUtxoViewMappingsForAccessGroupMemberOperationRemove: ExtraData should be empty for OperationTypeRemove, but received (ExtraData=%v) for "+
					"member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.ExtraData, accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}

		// Fetch the access group member entry for each member from the transaction metadata.
		existingGroupMemberEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
			NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
		if err != nil {
			return nil, errors.Wrapf(err, "_setUtxoViewMappingsForAccessGroupMemberOperationRemove: "+
				"Problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
		// We have to make sure this member entry has been added in a previous transaction, and that the member entry wasn't deleted.
		// By inverse, it means we will error when the entry is nil or has been deleted.
		if existingGroupMemberEntry == nil || existingGroupMemberEntry.isDeleted {
			return nil, errors.Wrapf(RuleErrorAccessGroupMemberDoesntExistOrIsDeleted,
				"_setUtxoViewMappingsForAccessGroupMemberOperationRemove: member doesn't exist or has been or already deleted, can't delete the "+
					"member again with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}

		// Add the existing access member group entry to our list of previous entries. Make copy to it so that we
		// don't get some unexpected results if we ever modify the UtxoView entry.
		//
		// TODO: Note that the map data isn't being copied, whichi could result in bugs on disconnects. Ignoring
		// for now because we're going to get rid of disconnects.
		existingGroupMemberEntryCopy := *existingGroupMemberEntry
		prevAccessGroupMemberEntries = append(prevAccessGroupMemberEntries, &existingGroupMemberEntryCopy)

		// Now delete the existing access group member entry.
		if err := bav._deleteAccessGroupMembershipKeyToAccessGroupMemberMapping(&existingGroupMemberEntryCopy, NewPublicKey(txMeta.AccessGroupOwnerPublicKey),
			NewGroupKeyName(txMeta.AccessGroupKeyName), blockHeight); err != nil {

			return nil, errors.Wrapf(err, "_setUtxoViewMappingsForAccessGroupMemberOperationRemove: "+
				"Problem deleting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
	}

	return prevAccessGroupMemberEntries, nil
}

func (bav *UtxoView) _setUtxoViewMappingsForAccessGroupMemberOperationUpdate(txMeta *AccessGroupMembersMetadata,
	blockHeight uint64) (_prevAccessGroupMemberEntries []*AccessGroupMemberEntry, _err error) {

	// Sanity-check that the operation type is correct.
	if txMeta.AccessGroupMemberOperationType != AccessGroupMemberOperationTypeUpdate {
		return nil, errors.Wrapf(RuleErrorAccessGroupMemberOperationTypeNotSupported,
			"_setUtxoViewMappingsForAccessGroupMemberOperationUpdate: "+
				"OperationType should be AccessGroupMemberOperationTypeUpdate, but received (OperationType=%v)",
			txMeta.AccessGroupMemberOperationType)
	}

	// AccessGroupMemberOperationTypeUpdate operation is used to update members in an access group.
	// In this operation, all the members specified in the transaction's metadata will be updated to the values
	// provided in the metadata.
	var prevAccessGroupMemberEntries []*AccessGroupMemberEntry
	for _, accessMember := range txMeta.AccessGroupMembersList {
		existingGroupMemberEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
			NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
		if err != nil {
			return nil, errors.Wrapf(err, "_setUtxoViewMappingsForAccessGroupMemberOperationUpdate: "+
				"Problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}

		if existingGroupMemberEntry == nil || existingGroupMemberEntry.isDeleted {
			return nil, errors.Wrapf(RuleErrorAccessGroupMemberDoesntExistOrIsDeleted,
				"_setUtxoViewMappingsForAccessGroupMemberOperationUpdate: member doesn't exist or has been or already deleted, can't update the "+
					"member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}

		// Sanity-check that the member entry's public key matches the public key in the transaction metadata.
		if existingGroupMemberEntry.AccessGroupMemberPublicKey == nil ||
			!bytes.Equal(existingGroupMemberEntry.AccessGroupMemberPublicKey.ToBytes(), accessMember.AccessGroupMemberPublicKey) {
			return nil, errors.Wrapf(RuleErrorAccessGroupMemberPublicKeyMismatch,
				"_setUtxoViewMappingsForAccessGroupMemberOperationUpdate: AccessGroupMemberPublicKey mismatch for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}

		// We will update the existing access group member entry with the new accessMember from the transaction metadata.
		existingGroupMemberEntryCopy := *existingGroupMemberEntry
		prevAccessGroupMemberEntries = append(prevAccessGroupMemberEntries, &existingGroupMemberEntryCopy)

		accessGroupMemberEntry := &AccessGroupMemberEntry{
			AccessGroupMemberPublicKey: existingGroupMemberEntryCopy.AccessGroupMemberPublicKey,
			AccessGroupMemberKeyName:   NewGroupKeyName(accessMember.AccessGroupMemberKeyName),
			EncryptedKey:               accessMember.EncryptedKey,
			ExtraData:                  accessMember.ExtraData,
		}
		if err := bav._setAccessGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMemberEntry,
			NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName)); err != nil {
			return nil, errors.Wrapf(err, "_setUtxoViewMappingsForAccessGroupMemberOperationUpdate: "+
				"Problem updating access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
				accessMember.AccessGroupMemberPublicKey, accessMember.AccessGroupMemberKeyName)
		}
	}

	return prevAccessGroupMemberEntries, nil
}

func (bav *UtxoView) validatePrevAccessGroupMemberEntries(txMeta *AccessGroupMembersMetadata, prevAccessGroupMemberEntries []*AccessGroupMemberEntry) error {
	// Sanity-check that the length of the prevAccessGroupMemberEntries list is the same as the member list in txn metadata, and that they match.
	switch txMeta.AccessGroupMemberOperationType {
	case AccessGroupMemberOperationTypeRemove, AccessGroupMemberOperationTypeUpdate:
		if len(txMeta.AccessGroupMembersList) != len(prevAccessGroupMemberEntries) {
			return errors.Wrapf(RuleErrorAccessGroupPrevMembersListIsIncorrect, "validatePrevAccessGroupMemberEntries: "+
				"Size of PrevAccessGroupMemberEntries array (Len=%v) differs from the length of the access group "+
				"members array in txn metadata (Len=%v). This should never happen.",
				len(txMeta.AccessGroupMembersList), len(prevAccessGroupMemberEntries))
		}
		// As a sanity-check we will iterate over all members in the prevAccessGroupMembers and ensure they match txMeta members.
		prevAccessGroupMemberPublicKeys := make(map[PublicKey]struct{})
		for _, prevAccessMember := range prevAccessGroupMemberEntries {
			if _, exists := prevAccessGroupMemberPublicKeys[*prevAccessMember.AccessGroupMemberPublicKey]; exists {
				return errors.Wrapf(RuleErrorAccessGroupPrevMembersListIsIncorrect, "validatePrevAccessGroupMemberEntries: "+
					"Failed sanity-check on prevAccessGroupMemberEntries, a duplicate access group member public key (%v) was found with ",
					*prevAccessMember.AccessGroupMemberPublicKey)
			}
			prevAccessGroupMemberPublicKeys[*prevAccessMember.AccessGroupMemberPublicKey] = struct{}{}
		}
		if len(prevAccessGroupMemberPublicKeys) != len(txMeta.AccessGroupMembersList) {
			return errors.Wrapf(RuleErrorAccessGroupPrevMembersListIsIncorrect, "validatePrevAccessGroupMemberEntries: Failed sanity-check "+
				"on length of prevAccessGroupMemberPublicKeys, was expecting (len=%v) but got (len=%v)",
				len(txMeta.AccessGroupMembersList), len(prevAccessGroupMemberPublicKeys))
		}
		for _, accessMember := range txMeta.AccessGroupMembersList {
			if _, exists := prevAccessGroupMemberPublicKeys[*NewPublicKey(accessMember.AccessGroupMemberPublicKey)]; !exists {
				return errors.Wrapf(RuleErrorAccessGroupPrevMembersListIsIncorrect, "validatePrevAccessGroupMemberEntries: "+
					"Failed sanity-check on existence of member public keys from txMeta in the prevAccessGroupMemberPublicKeys. "+
					"Was expecting that member with AccessGroupMemberPublicKey (%v) exists, but they don't",
					accessMember.AccessGroupMemberPublicKey)
			}
		}
	}

	return nil
}
