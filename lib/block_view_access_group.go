package lib

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
)

// GetAccessGroupEntry will check the membership index for membership of memberPublicKey in the group
// <groupOwnerPublicKey, groupKeyName>. Based on the blockheight, we fetch the full group or we fetch
// the simplified message group entry from the membership index. forceFullEntry is an optional parameter that
// will force us to always fetch the full group entry.
func (bav *UtxoView) GetAccessGroupEntry(memberPublicKey *PublicKey, groupOwnerPublicKey *PublicKey,
	groupKeyName *GroupKeyName, blockHeight uint32) (*AccessGroupEntry, error) {

	// If either of the provided parameters is nil, we return.
	if memberPublicKey == nil || groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil, fmt.Errorf("GetAccessGroupEntry: Called with nil parameter(s)")
	}

	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	if mapValue, exists := bav.AccessGroupKeyToAccessGroupEntry[*accessGroupKey]; exists {
		return mapValue, nil
	}

	// In case the group entry was not in utxo_view, nor was it in the membership index, we fetch the full group directly.
	return bav.GetAccessGroupEntryWithAccessGroupKey(accessGroupKey)
}

// GetAccessGroupForAccessGroupKeyExistence will check if the group with key accessGroupKey exists, if so it will fetch
// the simplified group entry from the membership index. If the forceFullEntry is set or if we're not past the membership
// index block height, then we will fetch the entire group entry from the db (provided it exists).
func (bav *UtxoView) GetAccessGroupForAccessGroupKeyExistence(accessGroupKey *AccessGroupKey,
	blockHeight uint32) (*AccessGroupEntry, error) {

	if accessGroupKey == nil {
		return nil, fmt.Errorf("GetAccessGroupForAccessGroupKeyExistence: Called with nil accessGroupKey")
	}

	// The owner is a member of their own group by default, hence they will be present in the membership index.
	ownerPublicKey := &accessGroupKey.AccessGroupOwnerPublicKey
	groupKeyName := &accessGroupKey.AccessGroupKeyName
	entry, err := bav.GetAccessGroupEntry(
		ownerPublicKey, ownerPublicKey, groupKeyName, blockHeight)
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
	accessGroupKey *AccessGroupKey) (*AccessGroupEntry, error) {
	// This function is used to get an AccessGroupEntry given an AccessGroupKey. The V3 messages are
	// backwards-compatible, and in particular each user has a built-in AccessGroupKey, called the
	// "base group key," which is simply an access key corresponding to user's main key.
	if EqualGroupKeyName(&accessGroupKey.AccessGroupKeyName, BaseGroupKeyName()) {
		return &AccessGroupEntry{
			AccessGroupOwnerPublicKey: NewPublicKey(accessGroupKey.AccessGroupOwnerPublicKey[:]),
			AccessGroupKeyName:        BaseGroupKeyName(),
			AccessGroupPublicKey:      NewPublicKey(accessGroupKey.AccessGroupOwnerPublicKey[:]),
		}, nil
	}

	// If an entry exists in the in-memory map, return the value of that mapping.
	if mapValue, exists := bav.AccessGroupKeyToAccessGroupEntry[*accessGroupKey]; exists {
		return mapValue, nil
	}

	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory UtxoView mapping.
	accessGroupEntry, err := DBGetAccessGroupEntryByAccessGroupId(bav.Handle, bav.Snapshot,
		&accessGroupKey.AccessGroupOwnerPublicKey, &accessGroupKey.AccessGroupKeyName)
	if err != nil {
		return nil, errors.Wrapf(err, "GetAccessGroupEntryWithAccessGroupKey: Problem getting "+
			"access group entry for access group key %v", accessGroupKey)
	}
	if accessGroupEntry != nil {
		if err := bav._setAccessGroupKeyToAccessGroupEntryMapping(&accessGroupKey.AccessGroupOwnerPublicKey, accessGroupEntry); err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupEntryWithAccessGroupKey: Problem setting "+
				"access group entry for access group key %v", accessGroupKey)
		}
	}
	return accessGroupEntry, nil
}

func (bav *UtxoView) _setAccessGroupKeyToAccessGroupEntryMapping(ownerPublicKey *PublicKey,
	accessGroupEntry *AccessGroupEntry) error {

	// This function shouldn't be called with a nil entry.
	if accessGroupEntry == nil {
		return fmt.Errorf("_setAccessGroupKeyToAccessGroupEntryMapping: Called with nil AccessGroupEntry; " +
			"this should never happen.")
	}

	// Create a key for the UtxoView mapping. We always put user's owner public key as part of the map key.
	// Note that this is different from message entries, which are indexed by access public keys.
	accessKey := AccessGroupKey{
		AccessGroupOwnerPublicKey: *ownerPublicKey,
		AccessGroupKeyName:        *accessGroupEntry.AccessGroupKeyName,
	}
	bav.AccessGroupKeyToAccessGroupEntry[accessKey] = accessGroupEntry
	return nil
}

func (bav *UtxoView) _deleteAccessGroupKeyToAccessGroupEntryMapping(ownerPublicKey *PublicKey,
	accessGroupEntry *AccessGroupEntry) error {

	if accessGroupEntry == nil {
		return fmt.Errorf("_deleteAccessGroupKeyToAccessGroupEntryMapping: Called with nil AccessGroupEntry; " +
			"this should never happen.")
	}

	// Create a tombstone entry.
	tombstoneAccessGroupEntry := *accessGroupEntry
	tombstoneAccessGroupEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	if err := bav._setAccessGroupKeyToAccessGroupEntryMapping(ownerPublicKey, &tombstoneAccessGroupEntry); err != nil {
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
		return errors.Wrapf(RuleErrorMessagingKeyNameTooShort, "ValidateAccessGroupPublicKeyAndName: "+
			"Too few characters in key name: min = %v, provided = %v",
			MinMessagingKeyNameCharacters, len(keyName))
	}
	if len(keyName) > MaxMessagingKeyNameCharacters {
		return errors.Wrapf(RuleErrorMessagingKeyNameTooLong, "ValidateAccessGroupPublicKeyAndName: "+
			"Too many characters in key name: max = %v; provided = %v",
			MaxMessagingKeyNameCharacters, len(keyName))
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
	accessGroupKey := NewAccessGroupKey(NewPublicKey(groupOwnerPublicKey), groupKeyName)
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
	accessGroupKey := NewAccessGroupKey(NewPublicKey(groupOwnerPublicKey), groupKeyName)
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

func (bav *UtxoView) _connectAccessGroupCreate(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Access groups are a part of DeSo V3 Messages.
	//
	// An AccessGroupKey is a pair of an <ownerPublicKey, groupKeyName>. AccessGroupKeys are registered on-chain
	// and are intended to be used as senders/recipients of privateMessage transactions, as opposed to users' main
	// keys. AccessGroupKeys solve the problem with messages for holders of derived keys, who previously had no
	// way to properly encrypt/decrypt messages, as they don't have access to user's main private key.
	//
	// A groupKeyName is a byte array between 1-32 bytes that labels the AccessGroupKey. Applications have the
	// choice to label users' AccessGroupKeys as they desire. For instance, a groupKeyName could represent the name
	// of an on-chain group chat. On the db level, groupKeyNames are always filled to 32 bytes with []byte(0) suffix.
	//
	// We hard-code two AccessGroupKeys:
	// 	[]byte{}              : user's ownerPublicKey. This key is registered for all users natively.
	//	[]byte("default-key") : intended to be registered when authorizing a derived key for the first time.
	//
	// The proposed flow is to register a default-key whenever first authorizing a derived key for a user. This way,
	// the derived key can be used for sending and receiving messages. DeSo V3 Messages also enable group chats, which
	// we will explain in more detail later.

	// Make sure DeSo V3 messages are live.
	if blockHeight < bav.Params.ForkHeights.DeSoV3MessagesBlockHeight {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessKeyBeforeBlockHeight, "_connectAccessGroupCreate: "+
				"Problem connecting access key, too early block height")
	}

	// Check that the transaction has the right TxnType.
	if txn.TxnMeta.GetTxnType() != TxnTypeAccessGroupCreate {
		return 0, 0, nil, fmt.Errorf("_connectAccessGroupCreate: called with bad TxnType %s",
			txn.TxnMeta.GetTxnType().String())
	}
	txMeta := txn.TxnMeta.(*AccessGroupCreateMetadata)

	// If the key name is just a list of 0s, then return because this name is reserved for the base key.
	if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), BaseGroupKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessKeyNameCannotBeZeros, "_connectAccessGroupCreate: "+
				"Cannot set a zeros-only key name?")
	}

	// Make sure that the access public key and the group key name have the correct format.
	if err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupPublicKey, txMeta.AccessGroupKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
			"Problem parsing public key: %v", txMeta.AccessGroupPublicKey)
	}

	// Sanity-check that transaction public key is valid.
	if err := IsByteArrayValidPublicKey(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
			"error %v", RuleErrorAccessOwnerPublicKeyInvalid)
	}

	// Sanity-check that we're not trying to add an access public key identical to the ownerPublicKey.
	if reflect.DeepEqual(txMeta.AccessGroupPublicKey, txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessPublicKeyCannotBeOwnerKey,
			"_connectAccessGroupCreate: access public key and txn public key can't be the same")
	}

	// Connect basic txn to get the total input and the total output without
	// considering the transaction metadata.
	totalInput, totalOutput, utxoOpsForTxn, err := bav._connectBasicTransfer(
		txn, txHash, blockHeight, verifySignatures)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: ")
	}

	// We have validated all information. At this point the inputs and outputs have been processed.
	// Now we need to handle the metadata. We will proceed to add the key to UtxoView, and generate UtxoOps.

	// We support "unencrypted" groups, which are a special-case of group chats that are intended for public
	// access. For example, this could be used to make discussion groups, which anyone can discover and join.
	// To do so, we hard-code an owner public key which will index all unencrypted group chats. We choose the
	// secp256k1 base element. Essentially, unencrypted groups are treated as access keys that are created
	// by the base element public key. To register an unencrypted group chat, the access key transaction
	// should contain the base element as the access public key. Below, we check for this and adjust the
	// accessGroupKey and accessPublicKey appropriately so that we can properly index the DB entry.
	var accessGroupKey *AccessGroupKey
	var accessPublicKey *PublicKey

	// First, let's check if this key doesn't already exist in UtxoView or in the DB.
	// It's worth noting that we index access keys by the owner public key and access key name.
	existingEntry, err := bav.GetAccessGroupEntryWithAccessGroupKey(accessGroupKey)
	if err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: ")
	}

	// Make sure that the utxoView entry and the transaction entries have the same access public keys and encrypted key.
	// The encrypted key is an auxiliary field that can be used to share the private key of the access public keys with
	// user's main key when registering an access key via a derived key. This field will also be used in group chats, as
	// we will later overload the AccessGroupEntry struct for storing access keys for group participants.
	if existingEntry != nil && !existingEntry.isDeleted {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupAlreadyExists,
			"_connectAccessGroupCreate: Access group already exists for access group owner public key %v "+
				"and access group key name %v", accessGroupKey.AccessGroupOwnerPublicKey, accessGroupKey.AccessGroupKeyName)
	}

	// merge extra data
	var extraData map[string][]byte
	if blockHeight >= bav.Params.ForkHeights.ExtraDataOnEntriesBlockHeight {
		var existingExtraData map[string][]byte
		if existingEntry != nil && !existingEntry.isDeleted {
			existingExtraData = existingEntry.ExtraData
		}
		extraData = mergeExtraData(existingExtraData, txn.ExtraData)
	}

	// TODO: Currently, it is technically possible for any user to add *any other* user to *any group* with
	// a garbage EncryptedKey. This can be filtered out at the app layer, though, and for now it leaves the
	// app layer with more flexibility compared to if we implemented an explicit permissioning model at the
	// consensus level.

	// Create an AccessGroupEntry, so we can add the entry to UtxoView.
	accessGroupEntry := &AccessGroupEntry{
		AccessGroupOwnerPublicKey: &accessGroupKey.AccessGroupOwnerPublicKey,
		AccessGroupKeyName:        &accessGroupKey.AccessGroupKeyName,
		AccessGroupPublicKey:      accessPublicKey,
		ExtraData:                 extraData,
	}

	if err := bav._setAccessGroupKeyToAccessGroupEntryMapping(&accessGroupKey.AccessGroupOwnerPublicKey, accessGroupEntry); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: ")
	}

	// Construct UtxoOperation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type: OperationTypeCreateAccessGroup,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectAccessGroupCreate(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is an AccessGroupKey operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAccessGroupCreate: utxoOperations are missing")
	}
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

	// Now we know the txMeta is AccessGroupKey
	txMeta := currentTxn.TxnMeta.(*AccessGroupCreateMetadata)

	// Sanity check that the access public key and key name are valid
	err := ValidateAccessGroupPublicKeyAndName(txMeta.AccessGroupOwnerPublicKey, txMeta.AccessGroupKeyName)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupCreate: failed validating the access "+
			"public key and key name")
	}

	// Get the access key that the transaction metadata points to.
	var accessKey *AccessGroupKey
	// TODO: Remove. We can define a separate db index for the discovery of unencrypted group chats.
	if reflect.DeepEqual(txMeta.AccessGroupPublicKey, GetS256BasePointCompressed()) {
		accessKey = NewAccessGroupKey(NewPublicKey(GetS256BasePointCompressed()), txMeta.AccessGroupKeyName)
	} else {
		accessKey = NewAccessGroupKey(NewPublicKey(currentTxn.PublicKey), txMeta.AccessGroupKeyName)
	}

	accessGroupEntry, err := bav.GetAccessGroupEntryWithAccessGroupKey(accessKey)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupCreate: Problem getting access group entry: ")
	}
	if accessGroupEntry == nil || accessGroupEntry.isDeleted {
		return fmt.Errorf("_disconnectBasicTransfer: Error, this key was already deleted "+
			"accessKey: %v", accessKey)
	}
	// sanity check that the existing entry matches the transaction metadata.
	if !reflect.DeepEqual(accessGroupEntry.AccessGroupOwnerPublicKey, txMeta.AccessGroupOwnerPublicKey) ||
		!reflect.DeepEqual(accessGroupEntry.AccessGroupKeyName, txMeta.AccessGroupKeyName) ||
		!reflect.DeepEqual(accessGroupEntry.AccessGroupPublicKey, txMeta.AccessGroupPublicKey) {
		return fmt.Errorf("_disconnectAccessGroupCreate: The existing access group entry doesn't match the "+
			"transaction metadata. Existing entry: %v, txMeta: %v", accessGroupEntry, txMeta)
	}

	// Delete this item from UtxoView to indicate we should remove this entry from DB.
	if err := bav._deleteAccessGroupKeyToAccessGroupEntryMapping(&accessKey.AccessGroupOwnerPublicKey, accessGroupEntry); err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroupCreate: Problem deleting access group entry: ")
	}
	// If the previous entry exists, we should set it in the utxoview

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
