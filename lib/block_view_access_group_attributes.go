package lib

// GetGroupEntryAttributeEntry returns the group entry attribute entry for the given group.
func (bav *UtxoView) GetGroupEntryAttributeEntry(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName) (*AttributeEntry, error) {
	//// Create accessGroupKey key.
	//accessGroupKey := NewAccessGroupId(groupOwnerPublicKey, groupKeyName[:])
	//// Check if attributeType exists for the accessGroupKey. Note: If accessGroupKey does not exist in the map, attributeType won't exist either.
	//if attributeEntry, exists := bav.GroupEntryAttributes[*accessGroupKey][attributeType]; exists {
	//	// AttributeEntry for this mapping holds IsSet bool and Value []byte.
	//	return attributeEntry, nil
	//}
	//
	//// If utxoView doesn't have the attribute entry, check the DB.
	//attributeEntry, err := DBGetAttributeEntryInGroupEntryAttributesIndex(bav.Handle, bav.Snapshot, groupOwnerPublicKey, groupKeyName, attributeType)
	//if err != nil {
	//	return nil, errors.Wrapf(err, "GetGroupEntryAttributeEntry: Problem fetching AttributeEntry from db: ")
	//}
	return nil, nil
}

// _setGroupEntryAttributeMapping sets the attribute status of a group.
func (bav *UtxoView) _setGroupEntryAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName, isSet bool, value []byte) error {
	//// Create accessGroupKey key.
	//accessGroupKey := NewAccessGroupId(groupOwnerPublicKey, groupKeyName[:])
	//// Create mapping if it doesn't exist.
	//if _, exists := bav.GroupEntryAttributes[*accessGroupKey]; !exists {
	//	bav.GroupEntryAttributes[*accessGroupKey] = make(map[AccessGroupEntryAttributeType]*AttributeEntry)
	//}
	//// Set attribute.
	//bav.GroupEntryAttributes[*accessGroupKey][attributeType] = NewAttributeEntry(isSet, value)
	return nil
}

// _deleteGroupEntryAttributeMapping deletes the entry from the GroupEntryAttributes mapping to undo any changes to
// attribute status in the current block.
func (bav *UtxoView) _deleteGroupEntryAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName) error {
	// Create accessGroupKey key.
	//accessGroupKey := NewAccessGroupId(groupOwnerPublicKey, groupKeyName[:])
	//// Delete attribute if it exists.
	//if _, exists := bav.GroupEntryAttributes[*accessGroupKey]; exists {
	//	delete(bav.GroupEntryAttributes[*accessGroupKey], attributeType)
	//}
	return nil
}

// GetGroupMemberAttributeEntry returns the group member attribute entry for the given group member.
func (bav *UtxoView) GetGroupMemberAttributeEntry(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	memberPublicKey *PublicKey) (*AttributeEntry, error) {
	//// Create enumeration key.
	//enumerationKey := NewGroupEnumerationKey(groupOwnerPublicKey, groupKeyName[:], memberPublicKey)
	//// Check if attributeType exists for the enumerationKey. Note: If enumerationKey does not exist in the map, attributeType won't exist either.
	//if attributeEntry, exists := bav.GroupMemberAttributes[*enumerationKey][attributeType]; exists {
	//	// AttributeEntry for this mapping holds IsSet bool and Value []byte.
	//	return attributeEntry, nil
	//}
	//
	//// If utxoView doesn't have the attribute entry, check the DB.
	//attributeEntry, err := DBGetAttributeEntryInGroupMemberAttributesIndex(bav.Handle, bav.Snapshot, groupOwnerPublicKey, groupKeyName, memberPublicKey, attributeType)
	//if err != nil {
	//	return nil, errors.Wrapf(err, "GetGroupMemberAttributeEntry: Problem fetching AttributeEntry from db: ")
	//}
	return nil, nil
}

// _setGroupMemberAttributeMapping sets the muted status of a member in the group.
func (bav *UtxoView) _setGroupMemberAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	memberPublicKey *PublicKey, isSet bool, value []byte) error {
	// Create enumeration key.
	//enumerationKey := NewGroupEnumerationKey(groupOwnerPublicKey, groupKeyName[:], memberPublicKey)
	//// Create mapping if it doesn't exist.
	//if _, exists := bav.GroupMemberAttributes[*enumerationKey]; !exists {
	//	bav.GroupMemberAttributes[*enumerationKey] = make(map[AccessGroupMemberAttributeType]*AttributeEntry)
	//}
	//// Set attribute.
	//bav.GroupMemberAttributes[*enumerationKey][attributeType] = NewAttributeEntry(isSet, value)
	return nil
}

// _deleteGroupMemberAttributeMapping deletes the entry from the GroupMemberAttributes mapping to undo any changes to
// attribute status in the current block.
func (bav *UtxoView) _deleteGroupMemberAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	memberPublicKey *PublicKey) error {
	//// Create enumeration key.
	//enumerationKey := NewGroupEnumerationKey(groupOwnerPublicKey, groupKeyName[:], memberPublicKey)
	//// Delete attribute if it exists.
	//if _, exists := bav.GroupMemberAttributes[*enumerationKey]; exists {
	//	delete(bav.GroupMemberAttributes[*enumerationKey], attributeType)
	//}
	return nil
}

func (bav *UtxoView) _connectAccessGroupAttributes(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	//// Make sure DeSo V3 messages are live.
	//if blockHeight < bav.Params.ForkHeights.DeSoV3MessagesBlockHeight {
	//	return 0, 0, nil, errors.Wrapf(
	//		RuleErrorAccessGroupsBeforeBlockHeight, "_connectAccessGroupAttributes: "+
	//			"DeSo V3 messages are not live yet.")
	//}
	//
	//// Check that the transaction has the right TxnType.
	//if txn.TxnMeta.GetTxnType() != TxnTypeAccessGroupAttributes {
	//	return 0, 0, nil, fmt.Errorf("_connectAccessGroupAttributes: called with bad TxnType %s",
	//		txn.TxnMeta.GetTxnType().String())
	//}
	//
	//// Get the transaction metadata.
	//txMeta := txn.TxnMeta.(*AccessGroupAttributesMetadata)
	//
	//// connect basic transfer to get the total input and the total output without
	//// considering the transaction metadata.
	//totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
	//	txn, txHash, blockHeight, verifySignatures)
	//if err != nil {
	//	return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupAttributes: "+
	//		"_connectBasicTransfer failed: ")
	//}
	//
	//// switch case for whether attribute holder is member, group, or message.
	//switch txMeta.AttributeHolderKey.(type) {
	//case *GroupEnumerationKey:
	//	// Make sure AttributeHolder is member
	//	if txMeta.AccessGroupAttributeHolder != AccessGroupAttributeHolderMember {
	//		return 0, 0, nil, errors.Wrapf(
	//			RuleErrorAccessGroupAttributesInvalidAttributeHolder, "_connectAccessGroupAttributes: "+
	//				"AttributeHolder is not member but attribute holder key is GroupEnumerationKey")
	//	}
	//
	//	groupOwnerPublicKey := &txMeta.AttributeHolderKey.(*GroupEnumerationKey).GroupOwnerPublicKey
	//	groupKeyName := &txMeta.AttributeHolderKey.(*GroupEnumerationKey).GroupKeyName
	//	memberPublicKey := &txMeta.AttributeHolderKey.(*GroupEnumerationKey).GroupMemberPublicKey
	//
	//	// TODO? Validate group public key and group key name.
	//
	//	// Make sure only the group owner can update the group attributes. In the future, we may want to allow
	//	// group members to update their own attributes on a case-by-case basis. (e.g. when a group member
	//	// wants to set "AcceptedInvitation" to true).
	//	if !reflect.DeepEqual(groupOwnerPublicKey, txn.PublicKey) {
	//		return 0, 0, nil, errors.Wrapf(
	//			RuleErrorAccessGroupAttributesOperationDenied, "_connectAccessGroupAttributes: "+
	//				"Only group owner can add attributes to group members")
	//	}
	//
	//	// Add or remove attribute based on operation type.
	//	switch txMeta.AccessGroupAttributeOperationType {
	//	case AccessGroupAttributeOperationTypeAdd:
	//		// Note: Attribute could already be added, we don't check for that. We simply overwrite it as a change-attribute value mechanism.
	//		// Add attribute to member.
	//		bav._setGroupMemberAttributeMapping(groupOwnerPublicKey, groupKeyName, memberPublicKey, AccessGroupMemberAttributeType(txMeta.AttributeType), true, txMeta.AttributeValue)
	//	case AccessGroupAttributeOperationTypeRemove:
	//		// Set attribute to false.
	//		bav._setGroupMemberAttributeMapping(groupOwnerPublicKey, groupKeyName, memberPublicKey, AccessGroupMemberAttributeType(txMeta.AttributeType), false, txMeta.AttributeValue)
	//	}
	//
	//case *AccessGroupKey:
	//	// Make sure AttributeHolder is group
	//	if txMeta.AccessGroupAttributeHolder != AccessGroupAttributeHolderGroup {
	//		return 0, 0, nil, errors.Wrapf(
	//			RuleErrorAccessGroupAttributesInvalidAttributeHolder, "_connectAccessGroupAttributes: "+
	//				"AttributeHolder is not group but attribute holder key is AccessGroupKey")
	//	}
	//
	//	groupOwnerPublicKey := &txMeta.AttributeHolderKey.(*AccessGroupKey).AccessGroupOwnerPublicKey
	//	groupKeyName := &txMeta.AttributeHolderKey.(*AccessGroupKey).AccessGroupKeyName
	//
	//	// TODO? Validate group public key and group key name.
	//
	//	// Make sure only the group owner can update the group attributes. In future, we may want to allow
	//	// group admins to update the group attributes as they will be treated as a de-facto group owner.
	//	if !reflect.DeepEqual(groupOwnerPublicKey, txn.PublicKey) {
	//		return 0, 0, nil, errors.Wrapf(
	//			RuleErrorAccessGroupAttributesOperationDenied, "_connectAccessGroupAttributes: "+
	//				"Only group owner can add attributes to group")
	//	}
	//
	//	// Add or remove attribute based on operation type.
	//	switch txMeta.AccessGroupAttributeOperationType {
	//	case AccessGroupAttributeOperationTypeAdd:
	//		// Note: Attribute could already be added, we don't check for that. We simply overwrite it as a change-attribute value mechanism.
	//		// Add attribute to group.
	//		bav._setGroupEntryAttributeMapping(groupOwnerPublicKey, groupKeyName, AccessGroupEntryAttributeType(txMeta.AttributeType), true, txMeta.AttributeValue)
	//	case AccessGroupAttributeOperationTypeRemove:
	//		// Set attribute to false.
	//		bav._setGroupEntryAttributeMapping(groupOwnerPublicKey, groupKeyName, AccessGroupEntryAttributeType(txMeta.AttributeType), false, txMeta.AttributeValue)
	//	}
	//
	////case *GroupChatMessageKey:
	////	// Make sure AttributeHolder is message
	////	if txMeta.AccessGroupAttributeHolder != AccessGroupAttributeHolderMessage {
	////		return 0, 0, nil, errors.Wrapf(
	////			RuleErrorAccessGroupAttributesInvalidAttributeHolder, "_connectAccessGroupAttributes: "+
	////				"AttributeHolder is not message but attribute holder key is GroupChatMessageKey")
	////	}
	////
	////	groupOwnerPublicKey := &txMeta.AttributeHolderKey.(*GroupChatMessageKey).GroupOwnerPublicKey
	////	groupKeyName := &txMeta.AttributeHolderKey.(*GroupChatMessageKey).AccessGroupKeyName
	////
	////	// TODO? Validate group public key and group key name.
	////
	////	//
	////case *DmMessageKey:
	////	// Make sure AttributeHolder is message
	////	if txMeta.AccessGroupAttributeHolder != AccessGroupAttributeHolderMessage {
	////		return 0, 0, nil, errors.Wrapf(
	////			RuleErrorAccessGroupAttributesInvalidAttributeHolder, "_connectAccessGroupAttributes: "+
	////				"AttributeHolder is not message but attribute holder key is DmMessageKey")
	////	}
	//
	//default:
	//	return 0, 0, nil, fmt.Errorf("_connectAccessGroupAttributes: called with bad AttributeHolderType: %v",
	//		txMeta.AccessGroupAttributeHolder)
	//}
	//
	//utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
	//	Type: OperationTypeAccessGroupAttributes,
	//	// TODO add new fields to utxoOperation for AccessGroupAttributes
	//})

	return 0, 0, nil, nil
}

func (bav *UtxoView) _disconnectAccessGroupAttributes(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// TODO: Implement this
	return nil
}
