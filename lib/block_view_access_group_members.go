package lib

import (
	"fmt"
	"github.com/pkg/errors"
)

// GetAccessGroupMemberEntry will check the membership index for membership of memberPublicKey in the group
// <groupOwnerPublicKey, groupKeyName>. Based on the blockheight, we fetch the full group or we fetch
// the simplified message group entry from the membership index. forceFullEntry is an optional parameter that
// will force us to always fetch the full group entry.
func (bav *UtxoView) GetAccessGroupMemberEntry(memberPublicKey *PublicKey, groupOwnerPublicKey *PublicKey,
	groupKeyName *GroupKeyName) (*AccessGroupMemberEntry, error) {

	// If either of the provided parameters is nil, we return.
	if memberPublicKey == nil || groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil, fmt.Errorf("GetAccessGroupMemberEntry: Called with nil memberPublicKey, groupOwnerPublicKey, or groupKeyName")
	}

	groupMembershipKey := NewGroupMembershipKey(*memberPublicKey, *groupOwnerPublicKey, *groupKeyName)

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	if mapValue, exists := bav.GroupMembershipKeyToAccessGroupMember[*groupMembershipKey]; exists {
		return mapValue, nil
	}

	// If we get here, it means that the group has not been fetched in this utxoView. We fetch it from the db.
	accessGroupMember, err := DBGetAccessGroupMemberEntry(bav.Handle, bav.Snapshot, *memberPublicKey, *groupOwnerPublicKey, *groupKeyName)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupMemberEntry: Problem fetching access group member entry")
	}
	// If member exists in DB, we also set the mapping in utxoView.
	if accessGroupMember != nil {
		if err := bav._setGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMember, groupOwnerPublicKey, groupKeyName); err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupMemberEntry: Problem setting group membership key to access group member mapping")
		}
	}
	return accessGroupMember, nil
}

// _setAccessGroupMemberEntry will set the membership mapping of AccessGroupMember.
func (bav *UtxoView) _setAccessGroupMemberEntry(accessGroupMemberEntry *AccessGroupMemberEntry,
	groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName, blockHeight uint32) error {

	// This function shouldn't be called with a nil member.
	if accessGroupMemberEntry == nil {
		return fmt.Errorf("_setAccessGroupMemberEntry: Called with nil accessGroupMemberEntry")
	}

	// If either of the provided parameters is nil, we return.
	if groupOwnerPublicKey == nil || groupKeyName == nil || accessGroupMemberEntry == nil {
		return fmt.Errorf("_setAccessGroupMemberEntry: Called with nil groupOwnerPublicKey, groupKeyName, or accessGroupMemberEntry")
	}

	// set utxoView mapping
	return errors.Wrapf(
		bav._setGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMemberEntry, groupOwnerPublicKey, groupKeyName),
		"_setAccessGroupMemberEntry: Problem setting group membership key to access group member mapping")
}

// _deleteAccessGroupMember will set the membership mapping of AccessGroupMember.isDeleted to true.
func (bav *UtxoView) _deleteAccessGroupMember(accessGroupMemberEntry *AccessGroupMemberEntry, groupOwnerPublicKey *PublicKey,
	groupKeyName *GroupKeyName) error {

	// This function shouldn't be called with a nil member.
	if accessGroupMemberEntry == nil || accessGroupMemberEntry.AccessGroupMemberPublicKey == nil ||
		groupOwnerPublicKey == nil || groupKeyName == nil {
		return fmt.Errorf("_deleteAccessGroupMember: Called with nil accessGroupMemberEntry, " +
			"accessGroupMemberEntry.AccessGroupMemberPublicKey, groupOwnerPublicKey, or groupKeyName")
	}

	// Create a tombstone entry.
	tombstoneAccessGroupMember := *accessGroupMemberEntry
	tombstoneAccessGroupMember.isDeleted = true

	// set utxoView mapping
	if err := bav._setGroupMembershipKeyToAccessGroupMemberMapping(&tombstoneAccessGroupMember, groupOwnerPublicKey, groupKeyName); err != nil {
		return errors.Wrapf(err, "_deleteAccessGroupMember: Problem setting group membership key to access group member mapping")
	}
	return nil
}

func (bav *UtxoView) _setGroupMembershipKeyToAccessGroupMemberMapping(accessGroupMemberEntry *AccessGroupMemberEntry,
	groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName) error {

	// This function shouldn't be called with a nil member.
	if accessGroupMemberEntry == nil || groupOwnerPublicKey == nil || groupKeyName == nil {
		return fmt.Errorf("_setGroupMembershipKeyToAccessGroupMemberMapping: " +
			"Called with nil accessGroupMemberEntry, groupOwnerPublicKey, or groupKeyName")
	}

	// Create group membership key.
	groupMembershipKey := *NewGroupMembershipKey(
		*accessGroupMemberEntry.AccessGroupMemberPublicKey, *groupOwnerPublicKey, *groupKeyName)
	// Set the mapping.
	bav.GroupMembershipKeyToAccessGroupMember[groupMembershipKey] = accessGroupMemberEntry
	return nil
}

func (bav *UtxoView) _connectAccessGroupMembers(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Make sure DeSo V3 messages are live.
	if blockHeight < bav.Params.ForkHeights.DeSoV3MessagesBlockHeight {
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

	// If the key name is just a list of 0s, then return because this name is reserved for the base key.
	if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), BaseGroupKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessKeyNameCannotBeZeros, "_connectAccessGroupMembers: "+
				"Problem connecting access group members: Cannot add members to base key.")
	}

	// Sanity check that transaction public key is valid.
	if err := IsByteArrayValidPublicKey(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: Invalid transaction public key: "+
			"%v with error: %v", txn.PublicKey, RuleErrorAccessOwnerPublicKeyInvalid)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: ")
	}

	// Make sure that the access group to which we want to add members exists.
	if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
		txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName, blockHeight); err != nil {

		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupDoesntExist, "_connectAccessGroupMembers: "+
				"Problem connecting access group members: Access group does not exist. Error: %v", err)
	}

	// Make sure there are no duplicate members with the same AccessGroupMemberPublicKey in the transaction's metadata.
	var accessGroupMemberPublicKeys map[PublicKey]struct{}
	for _, accessMember := range txMeta.AccessGroupMembersList {
		memberPublicKey := *NewPublicKey(accessMember.AccessGroupMemberPublicKey)
		if _, exists := accessGroupMemberPublicKeys[memberPublicKey]; !exists {
			accessGroupMemberPublicKeys[memberPublicKey] = struct{}{}
		} else {
			return 0, 0, nil, errors.Wrapf(
				RuleErrorAccessGroupMemberListDuplicateMember, "_connectAccessGroupMembers: "+
					"Problem connecting access group members: Access group member with public key (%v) "+
					"appears more than once in the AccessGroupMemberList.", memberPublicKey)
		}
	}

	// Determine the operation type.
	switch txMeta.AccessGroupMemberOperationType {
	case AccessGroupMemberOperationTypeAdd:
		// Validate all members.
		for _, accessMember := range txMeta.AccessGroupMembersList {
			// Encrypted public key cannot be empty, and has to have at least as many bytes as a generic private key.
			//
			// Note that if someone is adding themselves to an unencrypted group, then this value can be set to
			// zeros or G, the elliptic curve group element, which is also OK.

			// Make sure the accessMember public key and access key name are valid.
			// TODO:
			// 	1) Validate that the main group exists
			//  2) Validate that there are no overlapping members added in the same transaction.
			// 	3) Validate that the member's group exist
			// 	4) Validate that the member wasn't already added to the group.
			if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
				accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:], blockHeight); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: "+
					"Problem validating access group for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}

			// REVIEW FOLLOWING:
			// Now make sure accessMember's AccessGroupKey has already been added to UtxoView or DB.
			// We encrypt the groupAccessKey to recipients' access keys.
			memberGroupEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
				NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: "+
					"Problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}
			// If the access group member already exist, and wasn't deleted, we error because we can't add the same member twice.
			if memberGroupEntry != nil && !memberGroupEntry.isDeleted {
				return 0, 0, nil, errors.Wrapf(
					RuleErrorAccessMemberAlreadyExists, "_connectAccessGroupCreate: member already exists "+
						"for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}
		}
	case AccessGroupMemberOperationTypeRemove:
		// TODO: Implement this later
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupMemberOperationTypeNotSupported, "_connectAccessGroupCreate: "+
				"Operation type %v not supported yet.", txMeta.AccessGroupMemberOperationType)
	default:
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupMemberOperationTypeNotSupported, "_connectAccessGroupCreate: "+
				"Operation type %v not supported.", txMeta.AccessGroupMemberOperationType)
	}

	// Add the new access members to the utxo view.
	if txMeta.AccessGroupMemberOperationType == AccessGroupMemberOperationTypeAdd {
		for _, accessMember := range txMeta.AccessGroupMembersList {
			accessGroupMemberEntry := &AccessGroupMemberEntry{
				AccessGroupMemberPublicKey: NewPublicKey(accessMember.AccessGroupMemberPublicKey),
				AccessGroupMemberKeyName:   NewGroupKeyName(accessMember.AccessGroupMemberKeyName),
				EncryptedKey:               accessMember.EncryptedKey,
				ExtraData:                  accessMember.ExtraData,
			}

			if err := bav._setAccessGroupMemberEntry(accessGroupMemberEntry,
				NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName), blockHeight); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupMembers: "+
					"Problem setting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}
		}
	}

	// utxoOpsForTxn is an array of UtxoOperations. We append to it below to record the UtxoOperations
	// associated with this transaction.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeAccessGroupMembers,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectAccessGroupMembers(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last UtxoOperation is an AccessGroupMembersOperation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAccessGroupMembers: Trying to revert " +
			"AccessGroupMembersList but with no operations")
	}
	accessGroupMembersOp := utxoOpsForTxn[len(utxoOpsForTxn)-1]
	if accessGroupMembersOp.Type != OperationTypeAccessGroupMembers || operationType != OperationTypeAccessGroupMembers {
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
		txMeta.AccessGroupOwnerPublicKey[:], txMeta.AccessGroupKeyName[:], blockHeight); err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
			"Problem validating access public key or group key name for accessGroup (%v)", txMeta.AccessGroupOwnerPublicKey[:])
	}

	var addedAccessGroupMemberEntryList []*AccessGroupMemberEntry
	// Loop over members to make sure they are the same.
	switch txMeta.AccessGroupMemberOperationType {
	case AccessGroupMemberOperationTypeAdd:
		for _, accessMember := range txMeta.AccessGroupMembersList {
			// Make sure the accessMember public key and access key name are valid.
			if err := bav.ValidateAccessGroupPublicKeyAndNameWithUtxoView(
				accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:], blockHeight); err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
					"Problem validating public key or access key for member with "+
					"(AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}

			// Now make sure accessMember's AccessGroupKey has already been added to UtxoView or DB.
			// We encrypt the groupAccessKey to recipients' access keys.

			memberGroupEntry, err := bav.GetAccessGroupMemberEntry(NewPublicKey(accessMember.AccessGroupMemberPublicKey),
				NewPublicKey(txMeta.AccessGroupOwnerPublicKey), NewGroupKeyName(txMeta.AccessGroupKeyName))
			addedAccessGroupMemberEntryList = append(addedAccessGroupMemberEntryList, memberGroupEntry)
			if err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
					"Problem getting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}
			// If the access group member was already deleted, we error because there is nothing to do.
			if memberGroupEntry == nil || memberGroupEntry.isDeleted {
				return errors.Wrapf(
					RuleErrorAccessMemberDoesntExist, "_disconnectAccessGroupMembers: member doesn't exist "+
						"for member with (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName %v)",
					accessMember.AccessGroupMemberPublicKey[:], accessMember.AccessGroupMemberKeyName[:])
			}
		}
	}

	if txMeta.AccessGroupMemberOperationType == AccessGroupMemberOperationTypeAdd {
		if len(addedAccessGroupMemberEntryList) != len(txMeta.AccessGroupMembersList) {
			return fmt.Errorf("_disconnectAccessGroupMembers: addedAccessGroupMemberEntryList "+
				"length %d doesn't match txMeta.AccessGroupMembersList length %d",
				len(addedAccessGroupMemberEntryList), len(txMeta.AccessGroupMembersList))
		}

		for _, accessMemberEntry := range addedAccessGroupMemberEntryList {
			// Delete the access group member from the utxo view.
			if err := bav._deleteAccessGroupMember(accessMemberEntry, NewPublicKey(txMeta.AccessGroupOwnerPublicKey),
				NewGroupKeyName(txMeta.AccessGroupKeyName)); err != nil {
				return errors.Wrapf(err, "_disconnectAccessGroupMembers: "+
					"Problem deleting access group member entry for (AccessGroupMemberPublicKey: %v, AccessGroupMemberKeyName: %v)",
					accessMemberEntry.AccessGroupMemberPublicKey[:], accessMemberEntry.AccessGroupMemberKeyName[:])
			}
		}
	}

	// Now disconnect the basic transfer.
	operationIndex := len(utxoOpsForTxn) - 1
	return bav._disconnectBasicTransfer(currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
