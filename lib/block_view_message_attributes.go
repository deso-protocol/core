package lib

import "github.com/pkg/errors"

// GetDmMessageAttributeEntry returns the message attribute entry for the given message.
func (bav *UtxoView) GetDmMessageAttributeEntry(key DmMessageKey, attributeType MessageAttributeType) (*AttributeEntry, error) {
	// Check if attributeType exists for the key. Note: If key does not exist in the map, attributeType won't exist either.
	if attributeEntry, exists := bav.DmMessageAttributes[key][attributeType]; exists {
		// AttributeEntry for this mapping holds IsSet bool and Value []byte.
		return attributeEntry, nil
	}

	// If utxoView doesn't have the attribute entry, check the DB.
	attributeEntry, err := DBGetDmMessageAttributeEntryInMessageEntryAttributesIndex(bav.Handle, bav.Snapshot, key, attributeType)
	if err != nil {
		return nil, errors.Wrapf(err, "GetDmMessageAttributeEntry: Problem fetching AttributeEntry from db: ")
	}
	return attributeEntry, nil
}

// _setDmMessageAttributeEntry sets the message attribute entry for the given message.
func (bav *UtxoView) _setDmMessageAttributeEntry(key DmMessageKey, attributeType MessageAttributeType, isSet bool, value []byte) error {
	// Create mapping if it doesn't exist.
	if _, exists := bav.DmMessageAttributes[key]; !exists {
		bav.DmMessageAttributes[key] = make(map[MessageAttributeType]*AttributeEntry)
	}
	// Set attribute.
	bav.DmMessageAttributes[key][attributeType] = NewAttributeEntry(isSet, value)
	return nil
}

// _deleteDmMessageAttributeEntry deletes the message attribute entry for the given message.
func (bav *UtxoView) _deleteDmMessageAttributeEntry(key DmMessageKey, attributeType MessageAttributeType) error {
	// Delete attribute if it exists.
	if _, exists := bav.DmMessageAttributes[key]; exists {
		delete(bav.DmMessageAttributes[key], attributeType)
	}
	return nil
}

// GetGroupChatMessageAttributeEntry returns the message attribute entry for the given message.
func (bav *UtxoView) GetGroupChatMessageAttributeEntry(key GroupChatMessageKey, attributeType MessageAttributeType) (*AttributeEntry, error) {
	// Check if attributeType exists for the key. Note: If key does not exist in the map, attributeType won't exist either.
	if attributeEntry, exists := bav.GroupChatMessageAttributes[key][attributeType]; exists {
		// AttributeEntry for this mapping holds IsSet bool and Value []byte.
		return attributeEntry, nil
	}

	// If utxoView doesn't have the attribute entry, check the DB.
	attributeEntry, err := DBGetGroupChatMessageAttributeEntryInMessageEntryAttributesIndex(bav.Handle, bav.Snapshot, key, attributeType)
	if err != nil {
		return nil, errors.Wrapf(err, "GetGroupChatMessageAttributeEntry: Problem fetching AttributeEntry from db: ")
	}
	return attributeEntry, nil
}

// _setGroupChatMessageAttributeEntry sets the message attribute entry for the given message.
func (bav *UtxoView) _setGroupChatMessageAttributeEntry(key GroupChatMessageKey, attributeType MessageAttributeType, isSet bool, value []byte) error {
	// Create mapping if it doesn't exist.
	if _, exists := bav.GroupChatMessageAttributes[key]; !exists {
		bav.GroupChatMessageAttributes[key] = make(map[MessageAttributeType]*AttributeEntry)
	}
	// Set attribute.
	bav.GroupChatMessageAttributes[key][attributeType] = NewAttributeEntry(isSet, value)
	return nil
}

// _deleteGroupChatMessageAttributeEntry deletes the message attribute entry for the given message.
func (bav *UtxoView) _deleteGroupChatMessageAttributeEntry(key GroupChatMessageKey, attributeType MessageAttributeType) error {
	// Delete attribute if it exists.
	if _, exists := bav.GroupChatMessageAttributes[key]; exists {
		delete(bav.GroupChatMessageAttributes[key], attributeType)
	}
	return nil
}