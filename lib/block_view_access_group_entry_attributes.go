package lib

import "github.com/pkg/errors"

// GetGroupEntryAttributeEntry returns the group entry attribute entry for the given group.
func (bav *UtxoView) GetGroupEntryAttributeEntry(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	attributeType AccessGroupEntryAttributeType) (*AttributeEntry, error) {
	// Create accessGroupKey key.
	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
	// Check if accessGroupKey exists in GroupEntryAttributes mapping.
	attributeEntry, exists := bav.GroupEntryAttributes[*accessGroupKey][attributeType]
	if exists {
		// AttributeEntry for this mapping holds IsSet bool and Value []byte.
		return attributeEntry, nil
	}

	// If utxoView doesn't have the attribute entry, check the DB.
	attributeEntry, err := DBGetAttributeEntryInGroupEntryAttributesIndex(bav.Handle, bav.Snapshot, groupOwnerPublicKey, groupKeyName, attributeType)
	if err != nil {
		return nil, errors.Wrapf(err, "GetGroupEntryAttributeEntry: Problem fetching AttributeEntry from db: ")
	}
	return attributeEntry, nil
}

// _setGroupEntryAttributeMapping sets the attribute status of a group.
func (bav *UtxoView) _setGroupEntryAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	attributeType AccessGroupEntryAttributeType, isSet bool, value []byte) error {
	// Create accessGroupKey key.
	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
	// Create mapping if it doesn't exist.
	if _, exists := bav.GroupEntryAttributes[*accessGroupKey]; !exists {
		bav.GroupEntryAttributes[*accessGroupKey] = make(map[AccessGroupEntryAttributeType]*AttributeEntry)
	}
	// Set attribute.
	bav.GroupEntryAttributes[*accessGroupKey][attributeType] = NewAttributeEntry(isSet, value)
	return nil
}

// _deleteGroupEntryAttributeMapping deletes the entry from the GroupEntryAttributes mapping to undo any changes to
// attribute status in the current block.
func (bav *UtxoView) _deleteGroupEntryAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	attributeType AccessGroupEntryAttributeType) error {
	// Create accessGroupKey key.
	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
	// Delete attribute if it exists.
	if _, exists := bav.GroupEntryAttributes[*accessGroupKey]; exists {
		delete(bav.GroupEntryAttributes[*accessGroupKey], attributeType)
	}
	return nil
}
