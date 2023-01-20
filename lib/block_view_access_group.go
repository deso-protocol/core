package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"sort"
)

// GetAccessGroupEntry will fetch an access group entry corresponding to the provided access group id:
// <groupOwnerPublicKey, groupKeyName>.
func (bav *UtxoView) GetAccessGroupEntry(
	groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName) (*AccessGroupEntry, error) {

	// If either of the provided parameters is nil, we return.
	if groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil, fmt.Errorf("GetAccessGroupEntry: Called with nil parameter(s)")
	}
	accessGroupKey := NewAccessGroupId(groupOwnerPublicKey, groupKeyName[:])

	// We delegate the work to another variation of this function.
	return bav.GetAccessGroupEntryWithAccessGroupId(accessGroupKey)
}

// GetAccessGroupEntryWithAccessGroupId will fetch an access group entry corresponding to the provided access group id.
func (bav *UtxoView) GetAccessGroupEntryWithAccessGroupId(accessGroupId *AccessGroupId) (*AccessGroupEntry, error) {
	// This function is used to get an AccessGroupEntry given an AccessGroupId.
	// Each user has a built-in AccessGroupId, called the "base group key," which is simply an
	// access key corresponding to user's main key.
	if EqualGroupKeyName(&accessGroupId.AccessGroupKeyName, BaseGroupKeyName()) {
		return &AccessGroupEntry{
			AccessGroupOwnerPublicKey: NewPublicKey(accessGroupId.AccessGroupOwnerPublicKey[:]),
			AccessGroupKeyName:        BaseGroupKeyName(),
			AccessGroupPublicKey:      NewPublicKey(accessGroupId.AccessGroupOwnerPublicKey[:]),
		}, nil
	}

	// If an entry exists in the in-memory map, return the value of that mapping.
	if mapValue, exists := bav.AccessGroupIdToAccessGroupEntry[*accessGroupId]; exists {
		return mapValue, nil
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory UtxoView mapping.
	dbAdapter := bav.GetDbAdapter()
	accessGroupEntry, err := dbAdapter.GetAccessGroupEntryByAccessGroupId(accessGroupId)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupEntryWithAccessGroupId: Problem getting "+
			"access group entry for access group key %v", accessGroupId)
	}
	if accessGroupEntry != nil {
		if err := bav._setAccessGroupIdToAccessGroupEntryMapping(accessGroupEntry); err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupEntryWithAccessGroupId: Problem setting "+
				"access group entry for access group key %v", accessGroupId)
		}
	}
	return accessGroupEntry, nil
}

// GetAccessGroupExistenceWithAccessGroupId will return true or false depending on whether the access group
// entry corresponding to the provided access group id exists.
func (bav *UtxoView) GetAccessGroupExistenceWithAccessGroupId(accessGroupId *AccessGroupId) (bool, error) {

	// Base group exists for every user.
	if EqualGroupKeyName(&accessGroupId.AccessGroupKeyName, BaseGroupKeyName()) {
		return true, nil
	}

	// If an entry exists in the current UtxoView, we need to check whether it's deleted.
	if mapValue, exists := bav.AccessGroupIdToAccessGroupEntry[*accessGroupId]; exists {
		if mapValue == nil || mapValue.isDeleted {
			return false, nil
		}
		return true, nil
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return false.
	dbAdapter := bav.GetDbAdapter()
	existence, err := dbAdapter.GetAccessGroupExistenceByAccessGroupId(accessGroupId)
	if err != nil {
		return false, errors.Wrapf(err, "GetAccessGroupExistenceWithAccessGroupId: Problem getting "+
			"access group existence for access group id %v", accessGroupId)
	}
	return existence, nil
}

// GetAllAccessGroupIdsForUser will return all access group ids for the provided owner public key.
// Note that this function will return the base group key for every user, and there are possible overlaps
// between the _accessGroupIdsOwned and _accessGroupIdsMember lists, if user adds themselves as member of
// an access group they own. Returned AccessGroupIds are in random order.
func (bav *UtxoView) GetAllAccessGroupIdsForUser(ownerPublicKey []byte) (
	_accessGroupIdsOwned []*AccessGroupId, _accessGroupIdsMember []*AccessGroupId, _err error) {
	// This function will return all groups a user is associated with,
	// including the base key group, groups the user has created, and groups where
	// the user is a recipient.

	// This is our helper map to keep track of all user access keys.
	accessGroupIdsOwned, err := bav.GetAccessGroupIdsForOwner(ownerPublicKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetAllAccessGroupIdsForUser: Problem getting access group ids for owner")
	}
	accessGroupIdsMember, err := bav.GetAccessGroupIdsForMember(ownerPublicKey)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "GetAllAccessGroupIdsForUser: Problem getting access group ids for member")
	}
	return accessGroupIdsOwned, accessGroupIdsMember, nil
}

// GetAccessGroupIdsForOwner will return all access group ids that were registered for the provided owner public key.
// Note that this function will return the base group key for every user.
// Returned accessGroupIds are sorted lexicographically for convenience.
func (bav *UtxoView) GetAccessGroupIdsForOwner(ownerPublicKey []byte) (_accessGroupIdsOwned []*AccessGroupId, _err error) {
	// This function will return all access groups owned by the provided ownerPublicKey.
	if err := IsByteArrayValidPublicKey(ownerPublicKey); err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupIdsForOwner: Invalid owner public key: %v", ownerPublicKey)
	}
	ownerPk := NewPublicKey(ownerPublicKey)

	dbAdapter := bav.GetDbAdapter()
	accessGroupIdsDb, err := dbAdapter.GetAccessGroupIdsForOwner(ownerPk)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupIdsForOwner: Problem getting access groups for owner %v", ownerPublicKey)
	}

	// Add the db access group entries to a map.
	accessGroupIdsMap := make(map[AccessGroupId]struct{})
	for _, accessGroupId := range accessGroupIdsDb {
		groupId := NewAccessGroupId(ownerPk, accessGroupId.AccessGroupKeyName.ToBytes())
		accessGroupIdsMap[*groupId] = struct{}{}
	}
	// Add the base access group to the map.
	baseGroupId := NewAccessGroupId(ownerPk, BaseGroupKeyName().ToBytes())
	accessGroupIdsMap[*baseGroupId] = struct{}{}

	// Iterate over UtxoView mappings and merge the results with our map.
	for accessGroupIdIter, accessGroupEntryIter := range bav.AccessGroupIdToAccessGroupEntry {
		if !bytes.Equal(accessGroupIdIter.AccessGroupOwnerPublicKey.ToBytes(), ownerPk.ToBytes()) {
			continue
		}
		accessGroupId := accessGroupIdIter
		if accessGroupEntryIter.isDeleted {
			delete(accessGroupIdsMap, accessGroupId)
			continue
		}
		accessGroupIdsMap[accessGroupId] = struct{}{}
	}

	// Convert the map to a slice.
	accessGroupIds := []*AccessGroupId{}
	for accessGroupId := range accessGroupIdsMap {
		accessGroupIdCopy := accessGroupId
		accessGroupIds = append(accessGroupIds, &accessGroupIdCopy)
	}
	sort.Slice(accessGroupIds, func(ii, jj int) bool {
		return bytes.Compare(accessGroupIds[ii].ToBytes(), accessGroupIds[jj].ToBytes()) < 0
	})

	return accessGroupIds, nil
}

// GetAccessGroupIdsForMember will return all access group ids in which the provided memberPublicKey was added as member.
// Returned accessGroupIds are sorted lexicographically for convenience.
func (bav *UtxoView) GetAccessGroupIdsForMember(memberPublicKey []byte) (_accessGroupIds []*AccessGroupId, _err error) {
	// This function will return all access groups where the provided memberPublicKey is a member.
	if err := IsByteArrayValidPublicKey(memberPublicKey); err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupIdsForMember: Invalid member public key: %v", memberPublicKey)
	}
	memberPk := NewPublicKey(memberPublicKey)

	dbAdapter := bav.GetDbAdapter()
	accessGroupIdsForMemberDb, err := dbAdapter.GetAccessGroupIdsForMember(memberPk)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupIdsForMember: Problem getting access groups for member %v", memberPublicKey)
	}

	// Add the db access group entries to a map.
	accessGroupIdsForMemberMap := make(map[AccessGroupId]struct{})
	for _, accessGroupId := range accessGroupIdsForMemberDb {
		accessGroupIdsForMemberMap[*accessGroupId] = struct{}{}
	}

	// Iterate over UtxoView mappings and merge the results with our map.
	for accessGroupMembershipKeyIter, accessGroupMemberEntryIter := range bav.AccessGroupMembershipKeyToAccessGroupMember {
		if !bytes.Equal(accessGroupMembershipKeyIter.AccessGroupMemberPublicKey.ToBytes(), memberPk.ToBytes()) {
			continue
		}
		accessGroupMembershipKey := accessGroupMembershipKeyIter
		accessGroupId := NewAccessGroupId(
			&accessGroupMembershipKey.AccessGroupOwnerPublicKey, accessGroupMembershipKey.AccessGroupKeyName.ToBytes())
		if accessGroupMemberEntryIter.isDeleted {
			delete(accessGroupIdsForMemberMap, *accessGroupId)
			continue
		}
		accessGroupIdsForMemberMap[*accessGroupId] = struct{}{}
	}

	// Convert the map to a slice.
	accessGroupIdsForMember := []*AccessGroupId{}
	for accessGroupId := range accessGroupIdsForMemberMap {
		accessGroupIdCopy := accessGroupId
		accessGroupIdsForMember = append(accessGroupIdsForMember, &accessGroupIdCopy)
	}
	sort.Slice(accessGroupIdsForMember, func(ii, jj int) bool {
		return bytes.Compare(accessGroupIdsForMember[ii].ToBytes(), accessGroupIdsForMember[jj].ToBytes()) < 0
	})

	return accessGroupIdsForMember, nil
}

// _setAccessGroupIdToAccessGroupEntryMapping is a helper function that sets the mapping from an access group id to
// an access group entry in the UtxoView.
func (bav *UtxoView) _setAccessGroupIdToAccessGroupEntryMapping(accessGroupEntry *AccessGroupEntry) error {

	// This function shouldn't be called with a nil entry.
	if accessGroupEntry == nil || accessGroupEntry.AccessGroupOwnerPublicKey == nil || accessGroupEntry.AccessGroupKeyName == nil {
		return fmt.Errorf("_setAccessGroupIdToAccessGroupEntryMapping: Called with nil AccessGroupEntry, " +
			"AccessGroupEntry.AccessGroupOwnerPublicKey, or AccessGroupEntry.AccessGroupKeyName; this should never happen")
	}

	// Create a key for the UtxoView mapping.
	accessGroupId := accessGroupEntry.GetAccessGroupId()
	bav.AccessGroupIdToAccessGroupEntry[accessGroupId] = accessGroupEntry
	return nil
}

// _deleteAccessGroupIdToAccessGroupEntryMapping is a helper function that deletes the mapping from an access group id to
// an access group entry in the UtxoView.
func (bav *UtxoView) _deleteAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry *AccessGroupEntry) error {

	// This function shouldn't be called with a nil entry.
	if accessGroupEntry == nil || accessGroupEntry.AccessGroupOwnerPublicKey == nil || accessGroupEntry.AccessGroupKeyName == nil {
		return fmt.Errorf("_deleteAccessGroupKeyToAccessGroupEntryMapping: Called with nil AccessGroupEntry, " +
			"AccessGroupEntry.AccessGroupOwnerPublicKey, or AccessGroupEntry.AccessGroupKeyName; this should never happen")
	}

	// Create a tombstone entry.
	//
	// TODO: The copy we're creating still shares a map reference with the original. This means that
	// modifying the ExtraData map of the copy will affect the copy. This is OK for now because we
	// never do this, and also we're getting rid of disconnects soon so we won't need this function
	// after that hopefully.
	tombstoneAccessGroupEntry := *accessGroupEntry
	tombstoneAccessGroupEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	if err := bav._setAccessGroupIdToAccessGroupEntryMapping(&tombstoneAccessGroupEntry); err != nil {
		return errors.Wrapf(err, "_deleteAccessGroupKeyToAccessGroupEntryMapping: Problem setting "+
			"access group entry for access group key %v", accessGroupEntry)
	}

	return nil
}

// ValidateAccessGroupPublicKeyAndName validates that the provided access group public key and name are correctly formatted.
func ValidateAccessGroupPublicKeyAndName(accessGroupOwnerPublicKey, keyName []byte) error {
	// This is a helper function that allows us to verify messaging public key and key name.

	// First validate the accessGroupOwnerPublicKey.
	if err := IsByteArrayValidPublicKey(accessGroupOwnerPublicKey); err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndName: "+
			"Problem validating access group owner public key: %v", accessGroupOwnerPublicKey)
	}

	// If we get here, it means that we have a valid messaging public key.
	// Sanity-check messaging key name.
	if len(keyName) < MinMessagingKeyNameCharacters {
		return errors.Wrapf(RuleErrorAccessGroupKeyNameTooShort, "ValidateAccessGroupPublicKeyAndName: "+
			"Too few characters in key name: min = %v, provided = %v",
			MinAccessGroupKeyNameCharacters, len(keyName))
	}
	if len(keyName) > MaxMessagingKeyNameCharacters {
		return errors.Wrapf(RuleErrorAccessGroupKeyNameTooLong, "ValidateAccessGroupPublicKeyAndName: "+
			"Too many characters in key name: max = %v; provided = %v",
			MaxAccessGroupKeyNameCharacters, len(keyName))
	}
	return nil
}

// ValidateAccessGroupPublicKeyAndNameWithUtxoView validates that the provided access group public key and
// name are correctly formatted. It also checks that the access group exists based on the UtxoView.
func (bav *UtxoView) ValidateAccessGroupPublicKeyAndNameWithUtxoView(
	groupOwnerPublicKey, groupKeyName []byte, blockHeight uint32) error {

	// First validate the public key and name with ValidateGroupPublicKeyAndName
	err := ValidateAccessGroupPublicKeyAndName(groupOwnerPublicKey, groupKeyName)
	if err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: Failed validating "+
			"accessPublicKey and groupKeyName")
	}

	// Fetch the access key entry from UtxoView.
	accessGroupKey := NewAccessGroupId(NewPublicKey(groupOwnerPublicKey), groupKeyName)
	// To validate an access group key, we try to fetch the existence entry, which speeds up the lookup.
	groupExistence, err := bav.GetAccessGroupExistenceWithAccessGroupId(accessGroupKey)
	if err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: "+
			"Problem fetching access group entry")
	}
	if !groupExistence {
		return fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: non-existent access key entry "+
			"for groupOwnerPublicKey: %s", PkToString(groupOwnerPublicKey, bav.Params))
	}

	return nil
}

// Access group is the general abstraction for secure on-chain sharing of private keys such as encryption keys.
//
// An AccessGroup is identified by a pair of <accessGroupOwnerPublicKey, accessGroupKeyName>. Where
// accessGroupOwnerPublicKey is the public key of the user who registers the group (in this case also txn.PublicKey),
// and accessGroupKeyName is the 32-byte name of the group.
//
// Access group consist of the <accessGroupOwnerPublicKey, accessGroupKeyName> identifier pair, along with the
// accessGroupPublicKey, which is the public key that is shared within the access group. Together, this data forms
// access group metadata. The purpose of the _connectAccessGroup function and the AccessGroup transaction
// is to register this metadata.
//
// Aside from metadata, access groups also have members with whom the private key of the accessGroupPublicKey is shared.
// Access group members are added or updated in a separate transaction called AccessGroupMembers, which has its own connect
// function, namely _connectAccessGroupMembers. In addition, access groups can have extraData, which is a key-value map
// that are is to store additional information about the access group. Access group extraData is the main venue for
// utilizing the generality of access groups, ranging from on-chain private group chats, to private content.
func (bav *UtxoView) _connectAccessGroup(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Make sure access groups are live.
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupsBeforeBlockHeight, "_connectAccessGroup: "+
				"Problem connecting access key, too early block height")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAccessGroup {
		return 0, 0, nil, fmt.Errorf("_connectAccessGroup: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AccessGroupMetadata)

	// Sanity-check that the access group owner public key is the same as the transaction's sender. For now, groups can
	// only be registered for the sender's own public key.
	if !bytes.Equal(txn.PublicKey, txMeta.AccessGroupOwnerPublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupOwnerPublicKeyCannotBeDifferent,
			"_connectAccessGroup: access public key and txn public key must be the same")
	}

	// Make sure that the access group owner public key and the group key name have the correct format.
	if err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroup: "+
			"Problem parsing AccessGroupOwnerPublicKey: %v and group key name %v", txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName)
	}

	// Make sure that the access public key and the group key name have the correct format.
	if err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupPublicKey, txMeta.AccessGroupKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroup: "+
			"Problem parsing AccessGroupPublicKey: %v and group key name %v", txMeta.AccessGroupPublicKey, txMeta.AccessGroupKeyName)
	}

	// Sanity-check that we're not trying to add an access public key identical to the ownerPublicKey. This is reserved
	// for the base access group.
	if bytes.Equal(txMeta.AccessGroupPublicKey, txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessPublicKeyCannotBeOwnerKey,
			"_connectAccessGroup: access public key and txn public key can't be the same")
	}

	// If the key name is just a list of 0s, then return because this name is reserved for the base key access group.
	// The base key access group is a special group natively registered for every user. The base key access group
	// is an "access group expansion" of user's public key, i.e. accessGroupPublicKey = accessGroupOwnerPublicKey.
	// We decided to hard-code the base access group for convenience, since it's useful in some use-cases of access
	// such as DMs.
	if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), BaseGroupKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupsNameCannotBeZeros, "_connectAccessGroup: "+
				"Cannot set a zeros-only key name?")
	}

	// We have validated all transaction metadata information. We will proceed to add the access group to UtxoView.

	// Create the access group identifier key, as previously mentioned it is a pair of
	// <accessGroupOwnerPublicKey, accessGroupKeyName>.
	accessPublicKey := NewPublicKey(txMeta.AccessGroupPublicKey)
	accessGroupKey := &AccessGroupId{
		AccessGroupOwnerPublicKey: *NewPublicKey(txMeta.AccessGroupOwnerPublicKey),
		AccessGroupKeyName:        *NewGroupKeyName(txMeta.AccessGroupKeyName),
	}

	// Let's check if this key doesn't already exist in UtxoView or in the DB.
	existingEntry, err := bav.GetAccessGroupEntryWithAccessGroupId(accessGroupKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroup: ")
	}
	var prevAccessGroupEntry AccessGroupEntry

	switch txMeta.AccessGroupOperationType {
	case AccessGroupOperationTypeCreate:
		// If there already exists an access group with this key, then we return an error as we don't allow re-registering
		// access groups.
		if existingEntry != nil && !existingEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupAlreadyExists,
				"_connectAccessGroup: Access group already exists for access group owner public key %v "+
					"and access group key name %v",
				accessGroupKey.AccessGroupOwnerPublicKey, accessGroupKey.AccessGroupKeyName)
		}
	case AccessGroupOperationTypeUpdate:
		// If the group doesn't exist then we return an error.
		if existingEntry == nil || existingEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupDoesNotExist,
				"_connectAccessGroup: Access group doesn't exist for access group owner public key %v "+
					"and access group key name %v",
				accessGroupKey.AccessGroupOwnerPublicKey, accessGroupKey.AccessGroupKeyName)
		}
		prevAccessGroupEntry = *existingEntry
	default:
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupOperationTypeNotSupported,
			"_connectAccessGroup: Operation type %v not supported", txMeta.AccessGroupOperationType)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroup: ")
	}
	// Force the input to be non-zero so that we can prevent replay attacks.
	if totalInput == 0 {
		return 0, 0, nil, RuleErrorAccessGroupCreateRequiresNonZeroInput
	}

	// Create an AccessGroupEntry, so we can add the entry to UtxoView.
	accessGroupEntry := &AccessGroupEntry{
		AccessGroupOwnerPublicKey: &accessGroupKey.AccessGroupOwnerPublicKey,
		AccessGroupKeyName:        &accessGroupKey.AccessGroupKeyName,
		AccessGroupPublicKey:      accessPublicKey,
		ExtraData:                 txn.ExtraData,
	}

	if err := bav._setAccessGroupIdToAccessGroupEntryMapping(accessGroupEntry); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroup: ")
	}

	// Construct UtxoOperation. Since we can only set/unset an access group with _connect/_disconnect, we don't need to
	// store any information in the UtxoOperation. Transaction metadata is sufficient.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:                 OperationTypeAccessGroup,
		PrevAccessGroupEntry: &prevAccessGroupEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// _disconnectAccessGroup is the inverse of _connectAccessGroup. It deletes the access group from UtxoView.
func (bav *UtxoView) _disconnectAccessGroup(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Make sure access groups are live.
	if blockHeight < bav.Params.ForkHeights.AssociationsAndAccessGroupsBlockHeight {
		return errors.Wrapf(
			RuleErrorAccessGroupsBeforeBlockHeight, "_disconnectAccessGroup: "+
				"Problem disconnecting access group txn, too early block height")
	}

	// Verify that the last operation is an AccessGroup operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAccessGroup: utxoOperations are missing")
	}
	// If the last operation is not an AccessGroup operation, then we return an error.

	accessGroupOp := utxoOpsForTxn[len(utxoOpsForTxn)-1]
	if accessGroupOp.Type != OperationTypeAccessGroup {
		return fmt.Errorf("_disconnectAccessGroup: Trying to revert "+
			"OperationTypeAccessGroup but found type %v", accessGroupOp.Type)
	}

	// Check that the transaction has the right TxnType.
	if currentTxn.TxnMeta.GetTxnType() != TxnTypeAccessGroup {
		return fmt.Errorf("_disconnectAccessGroup: called with bad TxnType %s",
			currentTxn.TxnMeta.GetTxnType().String())
	}

	// Now we know the txMeta is AccessGroup
	txMeta := currentTxn.TxnMeta.(*AccessGroupMetadata)

	// Sanity check that the access public key and key name are valid
	err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroup: failed validating the access "+
			"public key and key name")
	}

	// Sanity-check that the access group owner public key is the same as the transaction's sender public key.
	if !bytes.Equal(txMeta.AccessGroupOwnerPublicKey, currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectAccessGroup: access group owner public key %v is "+
			"not the same as the transaction's sender public key %v", txMeta.AccessGroupOwnerPublicKey, currentTxn.PublicKey)
	}

	// Get the access key that the transaction metadata points to.
	accessKey := NewAccessGroupId(NewPublicKey(currentTxn.PublicKey), txMeta.AccessGroupKeyName)
	accessGroupEntry, err := bav.GetAccessGroupEntryWithAccessGroupId(accessKey)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroup: Problem getting access group entry: ")
	}
	// If the access group entry is nil or is deleted, then we return an error.
	if accessGroupEntry == nil || accessGroupEntry.isDeleted {
		return fmt.Errorf("_disconnectBasicTransfer: Error, this key was already deleted "+
			"accessKey: %v", accessKey)
	}
	// sanity check that the existing entry matches the transaction metadata.
	if !bytes.Equal(accessGroupEntry.AccessGroupOwnerPublicKey.ToBytes(), NewPublicKey(txMeta.AccessGroupOwnerPublicKey).ToBytes()) ||
		!bytes.Equal(accessGroupEntry.AccessGroupKeyName.ToBytes(), NewGroupKeyName(txMeta.AccessGroupKeyName).ToBytes()) ||
		!bytes.Equal(accessGroupEntry.AccessGroupPublicKey.ToBytes(), NewPublicKey(txMeta.AccessGroupPublicKey).ToBytes()) {
		return fmt.Errorf("_disconnectAccessGroup: The existing access group entry doesn't match the "+
			"transaction metadata. Existing entry: %v, txMeta: %v", accessGroupEntry, txMeta)
	}

	switch txMeta.AccessGroupOperationType {
	case AccessGroupOperationTypeCreate:
		// Delete this item from UtxoView to indicate we should remove this entry from DB.
		if err := bav._deleteAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry); err != nil {
			return errors.Wrapf(err, "_disconnectAccessGroup: Problem deleting access group entry: ")
		}
	case AccessGroupOperationTypeUpdate:
		// Verify that the previous access group entry is not nil.
		if accessGroupOp.PrevAccessGroupEntry == nil || accessGroupOp.PrevAccessGroupEntry.isDeleted {
			return fmt.Errorf("_disconnectAccessGroup: Error, trying to revert an update "+
				"operation but the previous access group entry is nil or is deleted, txMeta: %v", txMeta)
		}
		if !bytes.Equal(accessGroupOp.PrevAccessGroupEntry.AccessGroupOwnerPublicKey.ToBytes(), accessGroupEntry.AccessGroupOwnerPublicKey.ToBytes()) ||
			!bytes.Equal(accessGroupOp.PrevAccessGroupEntry.AccessGroupKeyName.ToBytes(), accessGroupEntry.AccessGroupKeyName.ToBytes()) {
			return fmt.Errorf("_disconnectAccessGroup: The previous access group entry doesn't match the "+
				"current access group entry. Previous entry: %v, current entry: %v", accessGroupOp.PrevAccessGroupEntry, accessGroupEntry)
		}
		// Set the access group entry to the previous access group entry.
		if err := bav._setAccessGroupIdToAccessGroupEntryMapping(accessGroupOp.PrevAccessGroupEntry); err != nil {
			return errors.Wrapf(err, "_disconnectAccessGroup: Problem setting access group entry: ")
		}
	}

	// Now disconnect the basic transfer.
	operationIndex := len(utxoOpsForTxn) - 1
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
