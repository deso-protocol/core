package lib

import (
	"bytes"
	"fmt"
	"github.com/pkg/errors"
	"reflect"
)

// GetAccessGroupEntry will check the membership index for membership of memberPublicKey in the group
// <groupOwnerPublicKey, groupKeyName>. Based on the blockheight, we fetch the full group or we fetch
// the simplified message group entry from the membership index. forceFullEntry is an optional parameter that
// will force us to always fetch the full group entry.
func (bav *UtxoView) GetAccessGroupEntry(groupOwnerPublicKey *PublicKey, groupKeyName *GroupKeyName,
	blockHeight uint32) (*AccessGroupEntry, error) {

	// If either of the provided parameters is nil, we return.
	if groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil, fmt.Errorf("GetAccessGroupEntry: Called with nil parameter(s)")
	}

	accessGroupKey := NewAccessGroupId(groupOwnerPublicKey, groupKeyName[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	if mapValue, exists := bav.AccessGroupIdToAccessGroupEntry[*accessGroupKey]; exists {
		return mapValue, nil
	}

	// In case the group entry was not in utxo_view, nor was it in the membership index, we fetch the full group directly.
	return bav.GetAccessGroupEntryWithAccessGroupKey(accessGroupKey)
}

// GetAccessGroupForAccessGroupKeyExistence will check if the group with key accessGroupKey exists, if so it will fetch
// the simplified group entry from the membership index. If the forceFullEntry is set or if we're not past the membership
// index block height, then we will fetch the entire group entry from the db (provided it exists).
func (bav *UtxoView) GetAccessGroupForAccessGroupKeyExistence(accessGroupKey *AccessGroupId,
	blockHeight uint32) (*AccessGroupEntry, error) {

	if accessGroupKey == nil {
		return nil, fmt.Errorf("GetAccessGroupForAccessGroupKeyExistence: Called with nil accessGroupKey")
	}

	// The owner is a member of their own group by default, hence they will be present in the membership index.
	ownerPublicKey := &accessGroupKey.AccessGroupOwnerPublicKey
	groupKeyName := &accessGroupKey.AccessGroupKeyName
	entry, err := bav.GetAccessGroupEntry(
		ownerPublicKey, groupKeyName, blockHeight)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupForAccessGroupKeyExistence: Problem getting "+
			"access group entry for access group key %v", accessGroupKey)
	}
	// Filter out deleted entries.
	if entry == nil || entry.isDeleted {
		return nil, nil
	}
	return entry, nil
}

func (bav *UtxoView) GetAccessGroupEntryWithAccessGroupKey(
	accessGroupId *AccessGroupId) (*AccessGroupEntry, error) {
	// This function is used to get an AccessGroupEntry given an AccessGroupId. The V3 messages are
	// backwards-compatible, and in particular each user has a built-in AccessGroupId, called the
	// "base group key," which is simply an access key corresponding to user's main key.
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
		return nil, errors.Wrapf(err, "GetAccessGroupEntryWithAccessGroupKey: Problem getting "+
			"access group entry for access group key %v", accessGroupId)
	}
	if accessGroupEntry != nil {
		if err := bav._setAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry); err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupEntryWithAccessGroupKey: Problem setting "+
				"access group entry for access group key %v", accessGroupId)
		}
	}
	return accessGroupEntry, nil
}

func (bav *UtxoView) _setAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry *AccessGroupEntry) error {

	// This function shouldn't be called with a nil entry.
	if accessGroupEntry == nil || accessGroupEntry.AccessGroupOwnerPublicKey == nil || accessGroupEntry.AccessGroupKeyName == nil {
		return fmt.Errorf("_setAccessGroupKeyToAccessGroupEntryMapping: Called with nil AccessGroupEntry, " +
			"AccessGroupEntry.AccessGroupOwnerPublicKey, or AccessGroupEntry.AccessGroupKeyName; this should never happen")
	}

	// Create a key for the UtxoView mapping. We always put user's owner public key as part of the map key.
	// Note that this is different from message entries, which are indexed by access public keys.
	accessKey := AccessGroupId{
		AccessGroupOwnerPublicKey: *accessGroupEntry.AccessGroupOwnerPublicKey,
		AccessGroupKeyName:        *accessGroupEntry.AccessGroupKeyName,
	}
	bav.AccessGroupIdToAccessGroupEntry[accessKey] = accessGroupEntry
	return nil
}

func (bav *UtxoView) _deleteAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry *AccessGroupEntry) error {

	// This function shouldn't be called with a nil entry.
	if accessGroupEntry == nil || accessGroupEntry.AccessGroupOwnerPublicKey == nil || accessGroupEntry.AccessGroupKeyName == nil {
		return fmt.Errorf("_deleteAccessGroupKeyToAccessGroupEntryMapping: Called with nil AccessGroupEntry, " +
			"AccessGroupEntry.AccessGroupOwnerPublicKey, or AccessGroupEntry.AccessGroupKeyName; this should never happen")
	}

	// Create a tombstone entry.
	tombstoneAccessGroupEntry := *accessGroupEntry
	tombstoneAccessGroupEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	if err := bav._setAccessGroupKeyToAccessGroupEntryMapping(&tombstoneAccessGroupEntry); err != nil {
		return errors.Wrapf(err, "_deleteAccessGroupKeyToAccessGroupEntryMapping: Problem setting "+
			"access group entry for access group key %v", accessGroupEntry)
	}

	return nil
}

func (bav *UtxoView) GetAccessGroupEntriesForUser(ownerPublicKey []byte, blockHeight uint32) (
	_accessGroupEntries []*AccessGroupEntry, _err error) {
	// This function will return all groups a user is associated with,
	// including the base key group, groups the user has created, and groups where
	// the user is a recipient.

	// This is our helper map to keep track of all user access keys.
	return nil, nil
}

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

// ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView validates public key and key name, which are used in DeSo V3 Messages protocol.
// The function first checks that the key and name are valid and then fetches an entry from UtxoView or DB
// to check if the key has been previously saved. This is particularly useful for connecting V3 messages.
func (bav *UtxoView) ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView(
	groupOwnerPublicKey, accessPublicKey, groupKeyName []byte, blockHeight uint32) error {

	// First validate the group public key and name with ValidateGroupPublicKeyAndName
	if err := ValidateGroupPublicKeyAndName(groupOwnerPublicKey, groupKeyName); err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: Failed validating "+
			"groupOwnerPublicKey and groupKeyName")
	}
	// First validate the access public key and name with ValidateGroupPublicKeyAndName
	if err := ValidateGroupPublicKeyAndName(accessPublicKey, groupKeyName); err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: Failed validating "+
			"accessPublicKey and groupKeyName")
	}

	// Fetch the access key entry from UtxoView.
	accessGroupKey := NewAccessGroupId(NewPublicKey(groupOwnerPublicKey), groupKeyName)
	// To validate an access group key, we try to fetch the simplified group entry from the membership index.
	accessGroupEntry, err := bav.GetAccessGroupForAccessGroupKeyExistence(accessGroupKey, blockHeight)
	if err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: "+
			"Problem fetching access group entry")
	}
	if accessGroupEntry == nil || accessGroupEntry.isDeleted {
		return fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: non-existent access key entry "+
			"for groupOwnerPublicKey: %s", PkToString(groupOwnerPublicKey, bav.Params))
	}

	// Compare the UtxoEntry with the provided key for more validation.
	if !reflect.DeepEqual(accessGroupEntry.AccessGroupPublicKey[:], accessPublicKey) {
		return fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: keys don't match for "+
			"groupOwnerPublicKey: %s", PkToString(groupOwnerPublicKey, bav.Params))
	}

	if !EqualGroupKeyName(accessGroupEntry.AccessGroupKeyName, NewGroupKeyName(groupKeyName)) {
		return fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: key name don't match for "+
			"groupOwnerPublicKey: %s", PkToString(groupOwnerPublicKey, bav.Params))
	}
	return nil
}

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
	// To validate an access group key, we try to fetch the simplified group entry from the membership index.
	accessGroupEntry, err := bav.GetAccessGroupForAccessGroupKeyExistence(accessGroupKey, blockHeight)
	if err != nil {
		return errors.Wrapf(err, "ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: "+
			"Problem fetching access group entry")
	}
	if accessGroupEntry == nil || accessGroupEntry.isDeleted {
		return fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: non-existent access key entry "+
			"for groupOwnerPublicKey: %s", PkToString(groupOwnerPublicKey, bav.Params))
	}

	// Sanity-check that the key name matches.
	if !EqualGroupKeyName(accessGroupEntry.AccessGroupKeyName, NewGroupKeyName(groupKeyName)) {
		return fmt.Errorf("ValidateAccessGroupPublicKeyAndNameAndAccessPublicKeyWithUtxoView: key name don't match for "+
			"groupOwnerPublicKey: %s", PkToString(groupOwnerPublicKey, bav.Params))
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
// access group metadata. The purpose of the _connectAccessGroupCreate function and the AccessGroupCreate transaction
// is to register this metadata.
//
// Aside from metadata, access groups also have members with whom the private key of the accessGrouPublicKey is shared.
// Access group members are added or updated in a separate transaction called AccessGroupMembers, which has its own connect
// function, namely _connectAccessGroupMembers. In addition, access group can have attributes, which are key-value pairs
// that are used to store additional information about the access group. Attributes are added or updated in a separate
// transaction called AccessGroupAttributes, which has its own connect function, namely _connectAccessGroupAttributes.
// Access group attributes are the main venue for utilizing the generality of access groups, ranging from on-chain private
// group chats, to private content.
func (bav *UtxoView) _connectAccessGroupCreate(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Make sure access groups are live.
	if blockHeight < bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupsBeforeBlockHeight, "_connectAccessGroupCreate: "+
				"Problem connecting access key, too early block height")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAccessGroupCreate {
		return 0, 0, nil, fmt.Errorf("_connectAccessGroupCreate: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AccessGroupCreateMetadata)

	// Sanity-check that the access group owner public key is the same as the transaction's sender. For now, groups can
	// only be registered for the sender's own public key.
	if !bytes.Equal(txn.PublicKey, txMeta.AccessGroupOwnerPublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupOwnerPublicKeyCannotBeDifferent,
			"_connectAccessGroupCreate: access public key and txn public key must be the same")
	}

	// Make sure that the access public key and the group key name have the correct format.
	if err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupPublicKey, txMeta.AccessGroupKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
			"Problem parsing public key: %v", txMeta.AccessGroupPublicKey)
	}

	// Sanity-check that we're not trying to add an access public key identical to the ownerPublicKey. This is reserved
	// for the base access group.
	if bytes.Equal(txMeta.AccessGroupPublicKey, txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessPublicKeyCannotBeOwnerKey,
			"_connectAccessGroupCreate: access public key and txn public key can't be the same")
	}

	// If the key name is just a list of 0s, then return because this name is reserved for the base key access group.
	// The base key access group is a special group natively registered for every user. The base key access group
	// is an "access group expansion" of user's public key, i.e. accessGroupPublicKey = accessGroupOwnerPublicKey.
	// We decided to hard-code the base access group for convenience, since it's useful in some use-cases of access
	// such as DMs.
	if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), BaseGroupKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessGroupsNameCannotBeZeros, "_connectAccessGroupCreate: "+
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
	existingEntry, err := bav.GetAccessGroupEntryWithAccessGroupKey(accessGroupKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: ")
	}

	// If there already exists an access group with this key, then we return an error as we don't allow re-registering
	// access groups.
	if existingEntry != nil && !existingEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupAlreadyExists,
			"_connectAccessGroupCreate: Access group already exists for access group owner public key %v "+
				"and access group key name %v", accessGroupKey.AccessGroupOwnerPublicKey, accessGroupKey.AccessGroupKeyName)
	}

	// merge extra data
	var extraData map[string][]byte
	if blockHeight >= bav.Params.ForkHeights.ExtraDataOnEntriesBlockHeight {
		extraData = mergeExtraData(make(map[string][]byte), txn.ExtraData)
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: ")
	}

	// Create an AccessGroupEntry, so we can add the entry to UtxoView.
	accessGroupEntry := &AccessGroupEntry{
		AccessGroupOwnerPublicKey: &accessGroupKey.AccessGroupOwnerPublicKey,
		AccessGroupKeyName:        &accessGroupKey.AccessGroupKeyName,
		AccessGroupPublicKey:      accessPublicKey,
		ExtraData:                 extraData,
	}

	if err := bav._setAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: ")
	}

	// Construct UtxoOperation. Since we can only set/unset an access group with _connect/_disconnect, we don't need to
	// store any information in the UtxoOperation. Transaction metadata is sufficient.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeCreateAccessGroup,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

// _disconnectAccessGroupCreate is the inverse of _connectAccessGroupCreate. It deletes the access group from UtxoView.
func (bav *UtxoView) _disconnectAccessGroupCreate(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an AccessGroupCreate operation.
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAccessGroupCreate: utxoOperations are missing")
	}
	// If the last operation is not an AccessGroupCreate operation, then we return an error.
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeCreateAccessGroup {
		return fmt.Errorf("_disconnectAccessGroupCreate: Trying to revert "+
			"OperationTypeCreateAccessGroup but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Check that the transaction has the right TxnType.
	if currentTxn.TxnMeta.GetTxnType() != TxnTypeAccessGroupCreate {
		return fmt.Errorf("_disconnectAccessGroupCreate: called with bad TxnType %s",
			currentTxn.TxnMeta.GetTxnType().String())
	}

	// Now we know the txMeta is AccessGroupCreate
	txMeta := currentTxn.TxnMeta.(*AccessGroupCreateMetadata)

	// Sanity check that the access public key and key name are valid
	err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupCreate: failed validating the access "+
			"public key and key name")
	}

	// Sanity-check that the access group owner public key is the same as the transaction's sender public key.
	if !bytes.Equal(txMeta.AccessGroupOwnerPublicKey, currentTxn.PublicKey) {
		return fmt.Errorf("_disconnectAccessGroupCreate: access group owner public key %v is "+
			"not the same as the transaction's sender public key %v", txMeta.AccessGroupOwnerPublicKey, currentTxn.PublicKey)
	}

	// Get the access key that the transaction metadata points to.
	accessKey := NewAccessGroupId(NewPublicKey(currentTxn.PublicKey), txMeta.AccessGroupKeyName)
	accessGroupEntry, err := bav.GetAccessGroupEntryWithAccessGroupKey(accessKey)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupCreate: Problem getting access group entry: ")
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
		return fmt.Errorf("_disconnectAccessGroupCreate: The existing access group entry doesn't match the "+
			"transaction metadata. Existing entry: %v, txMeta: %v", accessGroupEntry, txMeta)
	}

	// Delete this item from UtxoView to indicate we should remove this entry from DB.
	if err := bav._deleteAccessGroupKeyToAccessGroupEntryMapping(accessGroupEntry); err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupCreate: Problem deleting access group entry: ")
	}

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
