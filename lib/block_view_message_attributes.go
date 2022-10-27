package lib

// GetDmMessageAttributeEntry returns the message attribute entry for the given message.
func (bav *UtxoView) GetDmMessageAttributeEntry(key DmMessageKey, attributeType MessageAttributeType) (*AttributeEntry, error) {
	// TODO
	return nil, nil
}

// _setDmMessageAttributeEntry sets the message attribute entry for the given message.
func (bav *UtxoView) _setDmMessageAttributeEntry(key DmMessageKey, attributeType MessageAttributeType, isSet bool, value []byte) error {
	// TODO
	return nil
}

// _deleteDmMessageAttributeEntry deletes the message attribute entry for the given message.
func (bav *UtxoView) _deleteDmMessageAttributeEntry(key DmMessageKey, attributeType MessageAttributeType) error {
	// TODO
	return nil
}

// GetGroupChatMessageAttributeEntry returns the message attribute entry for the given message.
func (bav *UtxoView) GetGroupChatMessageAttributeEntry(key GroupChatMessageKey, attributeType MessageAttributeType) (*AttributeEntry, error) {
	// TODO
	return nil, nil
}

// _setGroupChatMessageAttributeEntry sets the message attribute entry for the given message.
func (bav *UtxoView) _setGroupChatMessageAttributeEntry(key GroupChatMessageKey, attributeType MessageAttributeType, isSet bool, value []byte) error {
	// TODO
	return nil
}

// _deleteGroupChatMessageAttributeEntry deletes the message attribute entry for the given message.
func (bav *UtxoView) _deleteGroupChatMessageAttributeEntry(key GroupChatMessageKey, attributeType MessageAttributeType) error {
	// TODO
	return nil
}

//// GetGroupEntryAttributeEntry returns the group entry attribute entry for the given group.
//func (bav *UtxoView) GetGroupEntryAttributeEntry(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
//	attributeType AccessGroupEntryAttributeType) (*AttributeEntry, error) {
//	// Create accessGroupKey key.
//	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
//	// Check if attributeType exists for the accessGroupKey. Note: If accessGroupKey does not exist in the map, attributeType won't exist either.
//	if attributeEntry, exists := bav.GroupEntryAttributes[*accessGroupKey][attributeType]; exists {
//		// AttributeEntry for this mapping holds IsSet bool and Value []byte.
//		return attributeEntry, nil
//	}
//
//	// If utxoView doesn't have the attribute entry, check the DB.
//	attributeEntry, err := DBGetAttributeEntryInGroupEntryAttributesIndex(bav.Handle, bav.Snapshot, groupOwnerPublicKey, groupKeyName, attributeType)
//	if err != nil {
//		return nil, errors.Wrapf(err, "GetGroupEntryAttributeEntry: Problem fetching AttributeEntry from db: ")
//	}
//	return attributeEntry, nil
//}
//
//// _setGroupEntryAttributeMapping sets the attribute status of a group.
//func (bav *UtxoView) _setGroupEntryAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
//	attributeType AccessGroupEntryAttributeType, isSet bool, value []byte) error {
//	// Create accessGroupKey key.
//	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
//	// Create mapping if it doesn't exist.
//	if _, exists := bav.GroupEntryAttributes[*accessGroupKey]; !exists {
//		bav.GroupEntryAttributes[*accessGroupKey] = make(map[AccessGroupEntryAttributeType]*AttributeEntry)
//	}
//	// Set attribute.
//	bav.GroupEntryAttributes[*accessGroupKey][attributeType] = NewAttributeEntry(isSet, value)
//	return nil
//}
//
//// _deleteGroupEntryAttributeMapping deletes the entry from the GroupEntryAttributes mapping to undo any changes to
//// attribute status in the current block.
//func (bav *UtxoView) _deleteGroupEntryAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
//	attributeType AccessGroupEntryAttributeType) error {
//	// Create accessGroupKey key.
//	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
//	// Delete attribute if it exists.
//	if _, exists := bav.GroupEntryAttributes[*accessGroupKey]; exists {
//		delete(bav.GroupEntryAttributes[*accessGroupKey], attributeType)
//	}
//	return nil
//}
