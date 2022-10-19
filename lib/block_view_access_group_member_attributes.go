package lib

import "github.com/pkg/errors"

// GetGroupMemberAttributeEntry returns the group member attribute entry for the given group member.
func (bav *UtxoView) GetGroupMemberAttributeEntry(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	memberPublicKey *PublicKey, attributeType AccessGroupMemberAttributeType) (*AttributeEntry, error) {
	// Create enumeration key.
	enumerationKey := NewGroupEnumerationKey(groupOwnerPublicKey, groupKeyName[:], memberPublicKey)
	// Check if enumerationKey exists in GroupMemberAttributes mapping.
	attributeEntry, exists := bav.GroupMemberAttributes[*enumerationKey][attributeType]
	if exists {
		// AttributeEntry for this mapping holds IsSet bool and Value []byte.
		return attributeEntry, nil
	}

	// If utxoView doesn't have the attribute entry, check the DB.
	attributeEntry, err := DBGetAttributeEntryInGroupMemberAttributesIndex(bav.Handle, bav.Snapshot, groupOwnerPublicKey, groupKeyName, memberPublicKey, attributeType)
	if err != nil {
		return nil, errors.Wrapf(err, "GetGroupMemberAttributeEntry: Problem fetching AttributeEntry from db: ")
	}
	return attributeEntry, nil
}

// _setGroupMemberAttributeMapping sets the muted status of a member in the group.
func (bav *UtxoView) _setGroupMemberAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	memberPublicKey *PublicKey, attributeType AccessGroupMemberAttributeType, isSet bool, value []byte) error {
	// Create enumeration key.
	enumerationKey := NewGroupEnumerationKey(groupOwnerPublicKey, groupKeyName[:], memberPublicKey)
	// Create mapping if it doesn't exist.
	if _, exists := bav.GroupMemberAttributes[*enumerationKey]; !exists {
		bav.GroupMemberAttributes[*enumerationKey] = make(map[AccessGroupMemberAttributeType]*AttributeEntry)
	}
	// Set attribute.
	bav.GroupMemberAttributes[*enumerationKey][attributeType] = NewAttributeEntry(isSet, value)
	return nil
}

// _deleteGroupMemberAttributeMapping deletes the entry from the GroupMemberAttributes mapping to undo any changes to
// attribute status in the current block.
func (bav *UtxoView) _deleteGroupMemberAttributeMapping(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	memberPublicKey *PublicKey, attributeType AccessGroupMemberAttributeType) error {
	// Create enumeration key.
	enumerationKey := NewGroupEnumerationKey(groupOwnerPublicKey, groupKeyName[:], memberPublicKey)
	// Delete attribute if it exists.
	if _, exists := bav.GroupMemberAttributes[*enumerationKey]; exists {
		delete(bav.GroupMemberAttributes[*enumerationKey], attributeType)
	}
	return nil
}
