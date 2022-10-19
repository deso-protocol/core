package lib

import (
	"bytes"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"reflect"
)

// GetAccessMember will check the membership index for membership of memberPublicKey in the group
// <groupOwnerPublicKey, groupKeyName>. Based on the blockheight, we fetch the full group or we fetch
// the simplified message group entry from the membership index. forceFullEntry is an optional parameter that
// will force us to always fetch the full group entry.
func (bav *UtxoView) GetAccessMember(memberPublicKey *PublicKey, groupOwnerPublicKey *PublicKey,
	groupKeyName *GroupKeyName, blockHeight uint32) *AccessGroupMember {

	// If either of the provided parameters is nil, we return.
	if memberPublicKey == nil || groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil
	}

	groupMembershipKey := NewGroupMembershipKey(memberPublicKey, groupOwnerPublicKey, groupKeyName[:])

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	if mapValue, exists := bav.GroupMembershipKeyToAccessGroupMember[*groupMembershipKey]; exists {
		return mapValue
	}

	// If we get here, it means that the group has not been fetched in this utxoView. We fetch it from the db.
	accessGroupMember := DBGetMemberFromMembershipIndex(bav.Handle, bav.Snapshot, memberPublicKey, groupOwnerPublicKey, groupKeyName)
	return accessGroupMember
}

// SetAccessMember will set the membership mapping of AccessGroupMember.
func (bav *UtxoView) SetAccessMember(accessGroupEntry *AccessGroupEntry,
	accessGroupMember *AccessGroupMember, blockHeight uint32) {

	// set utxoView mapping
	bav._setGroupMembershipKeyToAccessGroupMemberMapping(accessGroupEntry, accessGroupMember)
}

// GetAccessEntry will check the membership index for membership of memberPublicKey in the group
// <groupOwnerPublicKey, groupKeyName>. Based on the blockheight, we fetch the full group or we fetch
// the simplified message group entry from the membership index. forceFullEntry is an optional parameter that
// will force us to always fetch the full group entry.
func (bav *UtxoView) GetAccessEntry(memberPublicKey *PublicKey, groupOwnerPublicKey *PublicKey,
	groupKeyName *GroupKeyName, blockHeight uint32) *AccessGroupEntry {

	// If either of the provided parameters is nil, we return.
	if memberPublicKey == nil || groupOwnerPublicKey == nil || groupKeyName == nil {
		return nil
	}
	// If the group is the base key, then we return right away since base key cannot be modified by transactions.
	accessGroupKey := NewAccessGroupKey(groupOwnerPublicKey, groupKeyName[:])
	if EqualGroupKeyName(&accessGroupKey.GroupKeyName, BaseGroupKeyName()) {
		return &AccessGroupEntry{
			GroupOwnerPublicKey: NewPublicKey(accessGroupKey.OwnerPublicKey[:]),
			AccessPublicKey:     NewPublicKey(accessGroupKey.OwnerPublicKey[:]),
			AccessGroupKeyName:  BaseGroupKeyName(),
		}
	}

	// If the group has already been fetched in this utxoView, then we get it directly from there.
	if mapValue, exists := bav.AccessGroupKeyToAccessGroupEntry[*accessGroupKey]; exists {
		return mapValue
	}

	// In case the group entry was not in utxo_view, nor was it in the membership index, we fetch the full group directly.
	return bav.GetAccessGroupKeyToAccessGroupEntryMapping(accessGroupKey)
}

// GetAccessGroupForAccessGroupKeyExistence will check if the group with key accessGroupKey exists, if so it will fetch
// the simplified group entry from the membership index. If the forceFullEntry is set or if we're not past the membership
// index block height, then we will fetch the entire group entry from the db (provided it exists).
func (bav *UtxoView) GetAccessGroupForAccessGroupKeyExistence(accessGroupKey *AccessGroupKey,
	blockHeight uint32, forceFullEntry bool) *AccessGroupEntry {

	if accessGroupKey == nil {
		return nil
	}

	// The owner is a member of their own group by default, hence they will be present in the membership index.
	ownerPublicKey := &accessGroupKey.OwnerPublicKey
	groupKeyName := &accessGroupKey.GroupKeyName
	entry := bav.GetAccessEntry(
		ownerPublicKey, ownerPublicKey, groupKeyName, blockHeight)
	// Filter out deleted entries.
	if entry == nil || entry.isDeleted {
		return nil
	}
	return entry
}

func (bav *UtxoView) GetAccessGroupKeyToAccessGroupEntryMapping(
	accessGroupKey *AccessGroupKey) *AccessGroupEntry {
	// This function is used to get a AccessGroupEntry given a AccessGroupKey. The V3 messages are
	// backwards-compatible, and in particular each user has a built-in AccessGroupKey, called the
	// "base group key," which is simply a access key corresponding to user's main key.
	if EqualGroupKeyName(&accessGroupKey.GroupKeyName, BaseGroupKeyName()) {
		return &AccessGroupEntry{
			GroupOwnerPublicKey: NewPublicKey(accessGroupKey.OwnerPublicKey[:]),
			AccessPublicKey:     NewPublicKey(accessGroupKey.OwnerPublicKey[:]),
			AccessGroupKeyName:  BaseGroupKeyName(),
		}
	}

	// If an entry exists in the in-memory map, return the value of that mapping.
	if mapValue, exists := bav.AccessGroupKeyToAccessGroupEntry[*accessGroupKey]; exists {
		return mapValue
	}

	// Temporarily commenting out postgres until AccessGroup transaction are fixed.
	//if bav.Postgres != nil {
	//	var pgAccessGroup PGAccessGroup
	//	err := bav.Postgres.db.Model(&pgAccessGroup).Where("group_owner_public_key = ? and access_group_key_name = ?",
	//		accessGroupKey.OwnerPublicKey, accessGroupKey.GroupKeyName).First()
	//	if err != nil {
	//		return nil
	//	}
	//
	//	memberEntries := []*AccessGroupMember{}
	//	if err := gob.NewDecoder(
	//		bytes.NewReader(pgAccessGroup.DEPRECATED_AccessGroupMembers)).Decode(&memberEntries); err != nil {
	//		glog.Errorf("Error decoding DEPRECATED_AccessGroupMembers from DB: %v", err)
	//		return nil
	//	}
	//
	//	accessGroupEntry := &AccessGroupEntry{
	//		GroupOwnerPublicKey:   pgAccessGroup.GroupOwnerPublicKey,
	//		AccessPublicKey:    pgAccessGroup.AccessPublicKey,
	//		AccessGroupKeyName: pgAccessGroup.AccessGroupKeyName,
	//		DEPRECATED_AccessGroupMembers: memberEntries,
	//	}
	//	bav._setAccessGroupKeyToAccessGroupEntryMapping(&accessGroupKey.OwnerPublicKey, accessGroupEntry)
	//	return accessGroupEntry
	//
	//} else {
	// If we get here it means no value exists in our in-memory map. In this case,
	// defer to the db. If a mapping exists in the db, return it. If not, return
	// nil. Either way, save the value to the in-memory UtxoView mapping.
	accessGroupEntry := DBGetAccessGroupEntry(bav.Handle, bav.Snapshot, accessGroupKey)
	if accessGroupEntry != nil {
		bav._setAccessGroupKeyToAccessGroupEntryMapping(&accessGroupKey.OwnerPublicKey, accessGroupEntry)
	}
	return accessGroupEntry

	//}
}

func (bav *UtxoView) _setGroupMembershipKeyToAccessGroupMemberMapping(entry *AccessGroupEntry, member *AccessGroupMember) {
	if entry == nil || member == nil {
		return
	}
	groupMembershipKey := NewGroupMembershipKey(member.GroupMemberPublicKey, entry.GroupOwnerPublicKey, entry.AccessGroupKeyName[:])
	bav.GroupMembershipKeyToAccessGroupMember[*groupMembershipKey] = member
}

func (bav *UtxoView) _setAccessGroupKeyToAccessGroupEntryMapping(ownerPublicKey *PublicKey,
	accessGroupEntry *AccessGroupEntry) {

	// This function shouldn't be called with a nil entry.
	if accessGroupEntry == nil {
		glog.Errorf("_setAccessGroupKeyToAccessGroupEntryMapping: Called with nil AccessGroupEntry; " +
			"this should never happen.")
		return
	}

	// Create a key for the UtxoView mapping. We always put user's owner public key as part of the map key.
	// Note that this is different from message entries, which are indexed by access public keys.
	accessKey := AccessGroupKey{
		OwnerPublicKey: *ownerPublicKey,
		GroupKeyName:   *accessGroupEntry.AccessGroupKeyName,
	}
	bav.AccessGroupKeyToAccessGroupEntry[accessKey] = accessGroupEntry
}

func (bav *UtxoView) _deleteAccessGroupKeyToAccessGroupEntryMapping(ownerPublicKey *PublicKey,
	accessGroupEntry *AccessGroupEntry) {

	// Create a tombstone entry.
	tombstoneAccessGroupEntry := *accessGroupEntry
	tombstoneAccessGroupEntry.isDeleted = true

	// Set the mappings to point to the tombstone entry.
	bav._setAccessGroupKeyToAccessGroupEntryMapping(ownerPublicKey, &tombstoneAccessGroupEntry)
}

func (bav *UtxoView) GetAccessGroupEntriesForUser(ownerPublicKey []byte, blockHeight uint32) (
	_accessGroupEntries []*AccessGroupEntry, _err error) {
	// This function will return all groups a user is associated with,
	// including the base key group, groups the user has created, and groups where
	// the user is a recipient.

	// This is our helper map to keep track of all user access keys.
	accessKeysMap := make(map[AccessGroupKey]*AccessGroupEntry)

	// Start by fetching all the access keys that we have in the UtxoView.
	for accessKey, accessKeyEntry := range bav.AccessGroupKeyToAccessGroupEntry {
		// We don't check for deleted entries now, we will do that later once we add access keys
		// from the DB. For now we also omit the base key, we will add it later when querying the DB.

		// Check if the access key corresponds to our public key.
		if reflect.DeepEqual(accessKey.OwnerPublicKey[:], ownerPublicKey) {
			accessKeysMap[accessKey] = accessKeyEntry
			continue
		}
		// Now we will look for access keys where the public key is a recipient of a group chat.
		if blockHeight >= bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
			member, err := DBGetGroupMemberForAccessGroup(bav.Handle, bav.Snapshot, accessKeyEntry.GroupOwnerPublicKey, accessKeyEntry.AccessGroupKeyName, NewPublicKey(ownerPublicKey))
			if err != nil {
				return nil, errors.Wrapf(err, "GetAccessGroupEntriesForUser: Problem getting group members for access group: %v", accessKeyEntry)
			}
			if member != nil {
				accessKeysMap[accessKey] = accessKeyEntry
			}
		} else {
			for _, recipient := range accessKeyEntry.DEPRECATED_AccessGroupMembers {
				if reflect.DeepEqual(recipient.GroupMemberPublicKey[:], ownerPublicKey) {
					// If user is a recipient of a group chat, we need to add a modified access entry.
					accessKeysMap[accessKey] = accessKeyEntry
					break
				}
			}
		}

	}

	// We fetched all the entries from the UtxoView, so we move to the DB.
	var dbGroupEntries []*AccessGroupEntry
	var err error
	if blockHeight >= bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		dbGroupEntries, err = DBGetAllUserGroupEntries(bav.Handle, bav.Snapshot, ownerPublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupEntriesForUser: problem getting "+
				"access group entries from the DB")
		}
	} else {
		dbGroupEntries, err = DEPRECATEDDBGetAllUserGroupEntries(bav.Handle, ownerPublicKey)
		if err != nil {
			return nil, errors.Wrapf(err, "GetAccessGroupEntriesForUser: problem getting "+
				"access group entries from the DB")
		}
	}
	// Now go through the access group entries in the DB and add keys we haven't seen before.
	for _, accessGroupEntry := range dbGroupEntries {
		key := *NewAccessGroupKey(
			accessGroupEntry.GroupOwnerPublicKey, accessGroupEntry.AccessGroupKeyName[:])
		// Check if we have seen the access key before.
		if _, exists := accessKeysMap[key]; !exists {
			accessKeysMap[key] = accessGroupEntry
		}
	}

	// We have all the user's access keys in our map, so we now turn them into a list.
	var retAccessKeyEntries []*AccessGroupEntry
	for _, accessKeyEntry := range accessKeysMap {
		// Skip isDeleted entries
		if accessKeyEntry.isDeleted {
			continue
		}
		retAccessKeyEntries = append(retAccessKeyEntries, accessKeyEntry)
	}
	return retAccessKeyEntries, nil
}

func ValidateGroupPublicKeyAndName(accessPublicKey, keyName []byte) error {
	// This is a helper function that allows us to verify access public key and key name.

	// First validate the accessPublicKey.
	if err := IsByteArrayValidPublicKey(accessPublicKey); err != nil {
		return errors.Wrapf(err, "ValidateGroupPublicKeyAndName: "+
			"Problem validating sender's access key: %v", accessPublicKey)
	}

	// If we get here, it means that we have a valid access public key.
	// Sanity-check access key name.
	if len(keyName) < MinAccessKeyNameCharacters {
		return errors.Wrapf(RuleErrorAccessKeyNameTooShort, "ValidateGroupPublicKeyAndName: "+
			"Too few characters in key name: min = %v, provided = %v",
			MinAccessKeyNameCharacters, len(keyName))
	}
	if len(keyName) > MaxAccessKeyNameCharacters {
		return errors.Wrapf(RuleErrorAccessKeyNameTooLong, "ValidateGroupPublicKeyAndName: "+
			"Too many characters in key name: max = %v; provided = %v",
			MaxAccessKeyNameCharacters, len(keyName))
	}
	return nil
}

// ValidateKeyAndNameWithUtxo validates public key and key name, which are used in DeSo V3 Messages protocol.
// The function first checks that the key and name are valid and then fetches an entry from UtxoView or DB
// to check if the key has been previously saved. This is particularly useful for connecting V3 messages.
func (bav *UtxoView) ValidateKeyAndNameWithUtxo(ownerPublicKey, accessPublicKey, keyName []byte, blockHeight uint32) error {
	// First validate the public key and name with ValidateGroupPublicKeyAndName
	err := ValidateGroupPublicKeyAndName(accessPublicKey, keyName)
	if err != nil {
		return errors.Wrapf(err, "ValidateKeyAndNameWithUtxo: Failed validating "+
			"accessPublicKey and keyName")
	}

	// Fetch the access key entry from UtxoView.
	accessGroupKey := NewAccessGroupKey(NewPublicKey(ownerPublicKey), keyName)
	// To validate an access group key, we try to fetch the simplified group entry from the membership index.
	accessGroupEntry := bav.GetAccessGroupForAccessGroupKeyExistence(
		accessGroupKey, blockHeight, false)
	if accessGroupEntry == nil || accessGroupEntry.isDeleted {
		return fmt.Errorf("ValidateKeyAndNameWithUtxo: non-existent access key entry "+
			"for ownerPublicKey: %s", PkToString(ownerPublicKey, bav.Params))
	}

	// Compare the UtxoEntry with the provided key for more validation.
	if !reflect.DeepEqual(accessGroupEntry.AccessPublicKey[:], accessPublicKey) {
		return fmt.Errorf("ValidateKeyAndNameWithUtxo: keys don't match for "+
			"ownerPublicKey: %s", PkToString(ownerPublicKey, bav.Params))
	}

	if !EqualGroupKeyName(accessGroupEntry.AccessGroupKeyName, NewGroupKeyName(keyName)) {
		return fmt.Errorf("ValidateKeyAndNameWithUtxo: key name don't match for "+
			"ownerPublicKey: %s", PkToString(ownerPublicKey, bav.Params))
	}
	return nil
}

// getAccessGroupRotatingVersion returns the version of the access group key.
// The version is used to determine the key rotation period.
func getAccessGroupRotatingVersion(accessGroupEntry *AccessGroupEntry, blockHeight uint32) uint64 {
	rotatingVersion := uint64(0)
	if MigrationTriggered(uint64(blockHeight), DeSoAccessGroupsMigration) {
		// Extract ExtraData["MessageRotatingVersion"] from the entry.
		// if it's not present, leave it at 0.
		if val, exists := accessGroupEntry.ExtraData[MessageRotatingVersion]; exists {
			// convert the []byte value to uint64
			rotatingVersion = DecodeUint64(val)
		}
	}
	return rotatingVersion
}

// setAccessGroupRotatingVersion sets the version of the access group key.
// The version is used to determine the key rotation period.
func setAccessGroupRotatingVersion(accessGroupEntry *AccessGroupEntry, blockHeight uint32, rotatingVersion uint64) {
	if MigrationTriggered(uint64(blockHeight), DeSoAccessGroupsMigration) {
		// Set the ExtraData["MessageRotatingVersion"] to the provided value.
		accessGroupEntry.ExtraData[MessageRotatingVersion] = EncodeUint64(rotatingVersion)
	}
}

// getMessageEntryRotatingVersion returns the version of the access group key.
// The version is used to determine the key rotation period.
func getMessageEntryRotatingVersion(messageEntry *MessageEntry, blockHeight uint32) uint64 {
	rotatingVersion := uint64(0)
	if MigrationTriggered(uint64(blockHeight), DeSoAccessGroupsMigration) {
		// Extract ExtraData["MessageEntryRotatingVersion"] from the entry.
		// if it's not present, leave it at 0.
		if val, exists := messageEntry.ExtraData[MessageRotatingVersion]; exists {
			// convert the []byte value to uint64
			rotatingVersion = DecodeUint64(val)
		}
	}
	return rotatingVersion
}

// setMessageEntryRotatingVersion sets the version of the access group key.
// The version is used to determine the key rotation period.
func setMessageEntryRotatingVersion(messageEntry *MessageEntry, blockHeight uint32, rotatingVersion uint64) {
	if MigrationTriggered(uint64(blockHeight), DeSoAccessGroupsMigration) {
		// Set the ExtraData["MessageEntryRotatingVersion"] to the provided value.
		messageEntry.ExtraData[MessageRotatingVersion] = EncodeUint64(rotatingVersion)
	}
}

func (bav *UtxoView) _connectAccessGroupCreate(
	txn *MsgDeSoTxn, txHash *BlockHash, blockHeight uint32, verifySignatures bool) (
	_totalInput uint64, _totalOutput uint64, _utxoOps []*UtxoOperation, _err error) {

	// Access groups are a part of DeSo V3 Messages.
	//
	// A AccessGroupKey is a pair of an <ownerPublicKey, groupKeyName>. AccessGroupKeys are registered on-chain
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
	txMeta := txn.TxnMeta.(*AccessGroupMetadata)

	// If the key name is just a list of 0s, then return because this name is reserved for the base key.
	if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), BaseGroupKeyName()) {
		return 0, 0, nil, errors.Wrapf(
			RuleErrorAccessKeyNameCannotBeZeros, "_connectAccessGroupCreate: "+
				"Cannot set a zeros-only key name?")
	}

	// Make sure that the access public key and the group key name have the correct format.
	if err := ValidateGroupPublicKeyAndName(txMeta.AccessPublicKey, txMeta.AccessGroupKeyName); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
			"Problem parsing public key: %v", txMeta.AccessPublicKey)
	}

	// Sanity-check that transaction public key is valid.
	if err := IsByteArrayValidPublicKey(txn.PublicKey); err != nil {
		return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
			"error %v", RuleErrorAccessOwnerPublicKeyInvalid)
	}

	// Sanity-check that we're not trying to add a access public key identical to the ownerPublicKey.
	if reflect.DeepEqual(txMeta.AccessPublicKey, txn.PublicKey) {
		return 0, 0, nil, errors.Wrapf(RuleErrorAccessPublicKeyCannotBeOwnerKey,
			"_connectAccessGroupCreate: access public key and txn public key can't be the same")
	}

	// We now have a valid access public key, key name, and owner public key.
	// The hard-coded default key is only intended to be registered by the owner, so we will require a signature.
	//
	// Note that we decided to relax this constraint after the fork height. Why? Because keeping it would have
	// required users to go through two confirmations when approving a key with MetaMask vs just one.
	if blockHeight < bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		if EqualGroupKeyName(NewGroupKeyName(txMeta.AccessGroupKeyName), DefaultGroupKeyName()) {
			// Verify the GroupOwnerSignature. it should be signature( accessPublicKey || accessKeyName )
			// We need to make sure the default access key was authorized by the master public key.
			// All other keys can be registered by derived keys.
			bytes := append(txMeta.AccessPublicKey, txMeta.AccessGroupKeyName...)
			if err := _verifyBytesSignature(txn.PublicKey, bytes, txMeta.GroupOwnerSignature, blockHeight, bav.Params); err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
					"Problem verifying signature bytes, error: %v", RuleErrorAccessGroupSignatureInvalid)
			}
		}
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
	if reflect.DeepEqual(txMeta.AccessPublicKey, GetS256BasePointCompressed()) {
		accessGroupKey = NewAccessGroupKey(NewPublicKey(GetS256BasePointCompressed()), txMeta.AccessGroupKeyName)
		_, keyPublic := btcec.PrivKeyFromBytes(btcec.S256(), Sha256DoubleHash(txMeta.AccessGroupKeyName)[:])
		accessPublicKey = NewPublicKey(keyPublic.SerializeCompressed())
	} else {
		accessGroupKey = NewAccessGroupKey(NewPublicKey(txn.PublicKey), txMeta.AccessGroupKeyName)
		accessPublicKey = NewPublicKey(txMeta.AccessPublicKey)
	}
	// First, let's check if this key doesn't already exist in UtxoView or in the DB.
	// It's worth noting that we index access keys by the owner public key and access key name.
	existingEntry := bav.GetAccessGroupKeyToAccessGroupEntryMapping(accessGroupKey)

	// We will update the existing entry if it exists, or otherwise create a new utxoView entry. The new entry can currently
	// only be created if the accessGroupOperation is AccessGroupOperationAddMembers. If we update the existing entry,
	// we will set its AccessMembers and MutedMembers to these new values based on the txn.
	var newAccessMembers []*AccessGroupMember
	var newMuteList []*AccessGroupMember
	var newUnmuteList []*AccessGroupMember

	// Determine the access group operation.
	var accessGroupOperation AccessGroupOperation
	if blockHeight < bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		accessGroupOperation = AccessGroupOperationAddMembers
	} else {
		accessGroupOperation, err = GetAccessGroupOperation(txn)
		if err != nil {
			return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
				"Problem getting access group operation")
		}
	}
	// Make sure that the utxoView entry and the transaction entries have the same access public keys and encrypted key.
	// The encrypted key is an auxiliary field that can be used to share the private key of the access public keys with
	// user's main key when registering a access key via a derived key. This field will also be used in group chats, as
	// we will later overload the AccessGroupEntry struct for storing access keys for group participants.
	if existingEntry != nil && !existingEntry.isDeleted {
		if !reflect.DeepEqual(existingEntry.AccessPublicKey[:], accessPublicKey[:]) {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessPublicKeyCannotBeDifferent,
				"_connectAccessGroupCreate: Access public key cannot differ from the existing entry")
		}
	}

	// Check what type of operation we are performing.
	switch accessGroupOperation {
	case AccessGroupOperationAddMembers:
		// Make sure blockHeight is before the muting fork height.
		if blockHeight < bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
			// In DeSo V3 Messages, a access key can initialize a group chat with more than two parties. In group chats, all
			// messages are encrypted to the group access public key. The group members are provided with an encrypted
			// private key of the group's accessPublicKey so that each of them can read the messages. We refer to
			// these group members as access members, and for each member we will store a AccessMember object with the
			// respective encrypted key. The encrypted key must be addressed to a registered groupKeyName for each member, e.g.
			// the base or the default key names. In particular, this design choice allows derived keys to read group messages.
			//
			// An AccessGroup transaction can either initialize a groupAccessKey or add more members. In the former case,
			// there will be no existing AccessGroupEntry; however, in the latter case there will be an entry present in DB
			// or UtxoView. When adding members, we need to make sure that the transaction isn't trying to change data about
			// existing members. An important limitation is that the current design doesn't support removing recipients. This
			// would be tricky to impose in consensus, considering that removed users can't *forget* the access private key.
			// Removing users can be facilitated in the application-layer, where we can issue a new group key and share it with
			// all valid members.

			// Map all members so that it's easier to check for overlapping members.
			existingMembers := make(map[PublicKey]bool)

			// Sanity-check a group's members can't contain the accessPublicKey.
			existingMembers[*accessPublicKey] = true

			// If we're adding more group members, then we need to make sure there are no overlapping members between the
			// transaction's entry, and the existing entry.
			if existingEntry != nil && !existingEntry.isDeleted {
				// We make sure we'll add at least one access member in the transaction.
				if len(txMeta.AccessGroupMembers) == 0 {
					return 0, 0, nil, errors.Wrapf(RuleErrorAccessKeyDoesntAddMembers,
						"_connectAccessGroupCreate: Can't update a access key without any new recipients")
				}

				// Now iterate through all existing members and make sure there are no overlaps.
				for _, existingMember := range existingEntry.DEPRECATED_AccessGroupMembers {
					if _, exists := existingMembers[*existingMember.GroupMemberPublicKey]; exists {
						return 0, 0, nil, errors.Wrapf(
							RuleErrorAccessMemberAlreadyExists, "_connectAccessGroupCreate: "+
								"Error, member already exists (%v)", existingMember.GroupMemberPublicKey)
					}

					// Add the existingMember to our helper structs.
					existingMembers[*existingMember.GroupMemberPublicKey] = true
					newAccessMembers = append(newAccessMembers, existingMember)
				}
			}

			// Validate all members.
			for _, accessMember := range txMeta.AccessGroupMembers {
				// Encrypted public key cannot be empty, and has to have at least as many bytes as a generic private key.
				//
				// Note that if someone is adding themselves to an unencrypted group, then this value can be set to
				// zeros or G, the elliptic curve group element, which is also OK.
				if len(accessMember.EncryptedKey) < btcec.PrivKeyBytesLen {
					return 0, 0, nil, errors.Wrapf(
						RuleErrorAccessMemberEncryptedKeyTooShort, "_connectAccessGroupCreate: "+
							"Problem validating accessMember encrypted key for accessMember (%v): Encrypted "+
							"key length %v less than the minimum allowed %v. If this is an unencrypted group "+
							"member, please set %v zeros for this value", accessMember.GroupMemberPublicKey[:],
						len(accessMember.EncryptedKey), btcec.PrivKeyBytesLen, btcec.PrivKeyBytesLen)
				}

				// Make sure the accessMember public key and access key name are valid.
				if err := ValidateGroupPublicKeyAndName(accessMember.GroupMemberPublicKey[:], accessMember.GroupMemberKeyName[:]); err != nil {
					return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
						"Problem validating public key or access key for accessMember (%v)", accessMember.GroupMemberPublicKey[:])
				}

				// Now make sure accessMember's AccessGroupKey has already been added to UtxoView or DB.
				// We encrypt the groupAccessKey to recipients' access keys.
				memberAccessGroupKey := NewAccessGroupKey(
					accessMember.GroupMemberPublicKey, accessMember.GroupMemberKeyName[:])
				memberGroupEntry := bav.GetAccessGroupKeyToAccessGroupEntryMapping(memberAccessGroupKey)
				// The access key has to exist and cannot be deleted.
				if memberGroupEntry == nil || memberGroupEntry.isDeleted {
					return 0, 0, nil, errors.Wrapf(
						RuleErrorAccessMemberKeyDoesntExist, "_connectAccessGroupCreate: "+
							"Problem verifying messaing key for accessMember (%v)", accessMember.GroupMemberPublicKey[:])
				}
				// The accessMember can't be already added to the list of existing members.
				if _, exists := existingMembers[*accessMember.GroupMemberPublicKey]; exists {
					return 0, 0, nil, errors.Wrapf(
						RuleErrorAccessMemberAlreadyExists, "_connectAccessGroupCreate: "+
							"Error, accessMember already exists (%v)", accessMember.GroupMemberPublicKey[:])
				}
				// Add the accessMember to our helper structs.
				existingMembers[*accessMember.GroupMemberPublicKey] = true
				newAccessMembers = append(newAccessMembers, accessMember)
			}

		} else { // blockHeight >= DeSoAccessGroupsBlockHeight
			// We use new optimized DB prefixes after this block height.

			// Validate all members.
			for _, accessMember := range txMeta.AccessGroupMembers {
				// Encrypted public key cannot be empty, and has to have at least as many bytes as a generic private key.
				//
				// Note that if someone is adding themselves to an unencrypted group, then this value can be set to
				// zeros or G, the elliptic curve group element, which is also OK.
				if len(accessMember.EncryptedKey) < btcec.PrivKeyBytesLen {
					return 0, 0, nil, errors.Wrapf(
						RuleErrorAccessMemberEncryptedKeyTooShort, "_connectAccessGroupCreate: "+
							"Problem validating accessMember encrypted key for accessMember (%v): Encrypted "+
							"key length %v less than the minimum allowed %v. If this is an unencrypted group "+
							"member, please set %v zeros for this value", accessMember.GroupMemberPublicKey[:],
						len(accessMember.EncryptedKey), btcec.PrivKeyBytesLen, btcec.PrivKeyBytesLen)
				}

				// Make sure the accessMember public key and access key name are valid.
				if err := ValidateGroupPublicKeyAndName(accessMember.GroupMemberPublicKey[:], accessMember.GroupMemberKeyName[:]); err != nil {
					return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: "+
						"Problem validating public key or access key for accessMember (%v)", accessMember.GroupMemberPublicKey[:])
				}

				// Now make sure accessMember's AccessGroupKey has already been added to UtxoView or DB.
				// We encrypt the groupAccessKey to recipients' access keys.
				memberAccessGroupKey := NewAccessGroupKey(
					accessMember.GroupMemberPublicKey, accessMember.GroupMemberKeyName[:])
				memberGroupEntry := bav.GetAccessGroupKeyToAccessGroupEntryMapping(memberAccessGroupKey)
				// The access key has to exist and cannot be deleted.
				if memberGroupEntry == nil || memberGroupEntry.isDeleted {
					return 0, 0, nil, errors.Wrapf(
						RuleErrorAccessMemberKeyDoesntExist, "_connectAccessGroupCreate: "+
							"Problem verifying access key for accessMember (%v)", accessMember.GroupMemberPublicKey[:])
				}

				// Add the accessMember to our helper structs.
				newAccessMembers = append(newAccessMembers, accessMember)
			}
		}

	case AccessGroupOperationMuteMembers:
		// Muting members assumes the group was already created.
		if existingEntry == nil || existingEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupDoesntExist,
				"_connectAccessGroupCreate: Can't mute members for a non-existent group")
		}
		// MUTING/UNMUTING functionality notes:
		// In DeSo V3 Messages, Group Chat Owners can now mute or unmute members. This essentially acts like a
		// "remove member from group" functionality, but can also be used to mute spammers in large channels.
		// Note: A muted member can still cryptographically read the past AND future messages in the group, however,
		// they cannot send messages to this group until they are unmuted by the group owner.
		// Optimization Problem and Solution:
		// Every time a new message arrives as a txn, we need to check inside _connectPrivateMessage() if the sender of
		// the message is muted or not. This would decide whether we reject a message txn or not. However, to check
		// that, we can't just fetch the entire AccessGroupEntry which may contains 1000s if not 100,000s of members.
		// Instead, we will make usage of the membership index. We will especially see this in the flushing logic.

		for _, newlyMutedMember := range txMeta.AccessGroupMembers {

			// Make sure GroupOwner is not muting herself
			if reflect.DeepEqual(newlyMutedMember.GroupMemberPublicKey[:], existingEntry.GroupOwnerPublicKey[:]) {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupOwnerMutingSelf,
					"_connectAccessGroupCreate: GroupOwner cannot mute herself (%v).", existingEntry.GroupOwnerPublicKey[:])
			}
			// Make sure we are muting a member that exists in the group.
			member := bav.GetAccessMember(newlyMutedMember.GroupMemberPublicKey, existingEntry.GroupOwnerPublicKey, existingEntry.AccessGroupKeyName, blockHeight)
			if member == nil {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessMemberNotInGroup,
					"_connectAccessGroupCreate: Can't mute a non-existent member (%v)", newlyMutedMember.GroupMemberPublicKey[:])
			}

			// Get group member attribute entry for this member.
			attributeEntry, err := bav.getGroupMemberAttributeEntry(existingEntry.GroupOwnerPublicKey, existingEntry.AccessGroupKeyName, newlyMutedMember.GroupMemberPublicKey, AccessGroupMemberAttributeIsMuted)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: Problem getting group member attribute entry")
			}
			// Check if the member is already muted.
			if attributeEntry != nil && attributeEntry.IsSet {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessMemberAlreadyMuted,
					"_connectAccessGroupCreate: Can't mute a member that's already muted")
			}

			// Add member to newMuteList
			newMuteList = append(newMuteList, newlyMutedMember)
		}

	case AccessGroupOperationUnmuteMembers:
		// Unmuting members assumes the group was already created.
		if existingEntry == nil || existingEntry.isDeleted {
			return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupDoesntExist,
				"_connectAccessGroupCreate: Can't mute members for a non-existent group")
		}

		for _, newlyUnmutedMember := range txMeta.AccessGroupMembers {

			// Make sure we are unmuting a member that exists in the group.
			member := bav.GetAccessMember(newlyUnmutedMember.GroupMemberPublicKey, existingEntry.GroupOwnerPublicKey, existingEntry.AccessGroupKeyName, blockHeight)
			if member == nil {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessMemberNotInGroup,
					"_connectAccessGroupCreate: Can't unmute a non-existent member (%v)", newlyUnmutedMember.GroupMemberPublicKey[:])
			}

			// GroupOwner unmuting herself is invalid because GroupOwner can never be muted in the first place
			if reflect.DeepEqual(newlyUnmutedMember.GroupMemberPublicKey[:], existingEntry.GroupOwnerPublicKey[:]) {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessGroupOwnerUnmutingSelf,
					"_connectAccessGroupCreate: GroupOwner cannot mute herself (%v).", existingEntry.GroupOwnerPublicKey[:])
			}

			// Get group member attribute entry for this member.
			attributeEntry, err := bav.getGroupMemberAttributeEntry(existingEntry.GroupOwnerPublicKey, existingEntry.AccessGroupKeyName, newlyUnmutedMember.GroupMemberPublicKey, AccessGroupMemberAttributeIsMuted)
			if err != nil {
				return 0, 0, nil, errors.Wrapf(err, "_connectAccessGroupCreate: Problem getting group member attribute entry")
			}
			// Check if the member is already unmuted.
			if attributeEntry == nil || !attributeEntry.IsSet {
				return 0, 0, nil, errors.Wrapf(RuleErrorAccessMemberAlreadyUnmuted,
					"_connectAccessGroupCreate: Can't unmute a member that's already unmuted")
			}

			// Add member to newUnmuteList
			newUnmuteList = append(newUnmuteList, newlyUnmutedMember)
		}

	default:
		// If we're here, then the operation type is invalid. Currently, this can only
		// happen if the operation is of type AccessGroupOperationRemoveMembers
		return 0, 0, nil, errors.Wrapf(err,
			"_connectAccessGroupCreate: Error, access group operation.")

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

	// Create a AccessGroupEntry so we can add the entry to UtxoView.
	accessGroupEntry := NewAccessGroupEntry(
		&accessGroupKey.OwnerPublicKey,
		accessPublicKey,
		NewGroupKeyName(txMeta.AccessGroupKeyName),
		newAccessMembers,
		extraData,
		uint64(blockHeight),
	)

	// Create a utxoOps entry, we make a copy of the existing entry.
	var prevAccessGroupEntry *AccessGroupEntry
	if existingEntry != nil && !existingEntry.isDeleted {
		prevAccessGroupEntry = &AccessGroupEntry{}
		rr := bytes.NewReader(EncodeToBytes(uint64(blockHeight), existingEntry))
		if exists, err := DecodeFromBytes(prevAccessGroupEntry, rr); !exists || err != nil {
			return 0, 0, nil, errors.Wrapf(err,
				"_connectAccessGroupCreate: Error decoding previous entry")
		}
	}

	// Set mappings and DB entries if blockHeight is greater than access groups fork height.
	if blockHeight >= bav.Params.ForkHeights.DeSoAccessGroupsBlockHeight {
		// Set mappings for newlyMutedMembers
		for _, newlyMutedMember := range newMuteList {
			bav.setGroupMemberAttributeMapping(accessGroupEntry.GroupOwnerPublicKey,
				accessGroupEntry.AccessGroupKeyName, newlyMutedMember.GroupMemberPublicKey,
				AccessGroupMemberAttributeIsMuted, true, nil)
		}
		// Set mappings for newlyUnmutedMembers
		for _, newlyUnmutedMember := range newUnmuteList {
			bav.setGroupMemberAttributeMapping(accessGroupEntry.GroupOwnerPublicKey,
				accessGroupEntry.AccessGroupKeyName, newlyUnmutedMember.GroupMemberPublicKey,
				AccessGroupMemberAttributeIsMuted, false, nil)
		}
	}

	bav._setAccessGroupKeyToAccessGroupEntryMapping(&accessGroupKey.OwnerPublicKey, accessGroupEntry)

	// Construct UtxoOperation.
	utxoOpsForTxn = append(utxoOpsForTxn, &UtxoOperation{
		Type:               OperationTypeAccessKey,
		PrevAccessKeyEntry: prevAccessGroupEntry,
	})

	return totalInput, totalOutput, utxoOpsForTxn, nil
}

func (bav *UtxoView) _disconnectAccessGroup(
	operationType OperationType, currentTxn *MsgDeSoTxn, txnHash *BlockHash,
	utxoOpsForTxn []*UtxoOperation, blockHeight uint32) error {

	// Verify that the last operation is a AccessGroupKey operation
	if len(utxoOpsForTxn) == 0 {
		return fmt.Errorf("_disconnectAccessGroup: utxoOperations are missing")
	}
	operationIndex := len(utxoOpsForTxn) - 1
	if utxoOpsForTxn[operationIndex].Type != OperationTypeAccessKey {
		return fmt.Errorf("_disconnectAccessGroup: Trying to revert "+
			"OperationTypeAccessKey but found type %v",
			utxoOpsForTxn[operationIndex].Type)
	}

	// Check that the transaction has the right TxnType.
	if currentTxn.TxnMeta.GetTxnType() != TxnTypeAccessGroupCreate {
		return fmt.Errorf("_disconnectAccessGroup: called with bad TxnType %s",
			currentTxn.TxnMeta.GetTxnType().String())
	}

	// Now we know the txMeta is AccessGroupKey
	txMeta := currentTxn.TxnMeta.(*AccessGroupMetadata)

	// Sanity check that the access public key and key name are valid
	err := ValidateGroupPublicKeyAndName(txMeta.AccessPublicKey, txMeta.AccessGroupKeyName)
	if err != nil {
		return errors.Wrapf(err, "_disconnectAccessGroup: failed validating the access "+
			"public key and key name")
	}

	// Get the access key that the transaction metadata points to.
	var accessKey *AccessGroupKey
	if reflect.DeepEqual(txMeta.AccessPublicKey, GetS256BasePointCompressed()) {
		accessKey = NewAccessGroupKey(NewPublicKey(GetS256BasePointCompressed()), txMeta.AccessGroupKeyName)
	} else {
		accessKey = NewAccessGroupKey(NewPublicKey(currentTxn.PublicKey), txMeta.AccessGroupKeyName)
	}

	accessKeyEntry := bav.GetAccessGroupKeyToAccessGroupEntryMapping(accessKey)
	if accessKeyEntry == nil || accessKeyEntry.isDeleted {
		return fmt.Errorf("_disconnectBasicTransfer: Error, this key was already deleted "+
			"accessKey: %v", accessKey)
	}
	prevAccessKeyEntry := utxoOpsForTxn[operationIndex].PrevAccessKeyEntry
	// sanity check that the prev entry and current entry match
	if prevAccessKeyEntry != nil {
		if !reflect.DeepEqual(accessKeyEntry.AccessPublicKey[:], prevAccessKeyEntry.AccessPublicKey[:]) ||
			!reflect.DeepEqual(accessKeyEntry.GroupOwnerPublicKey[:], prevAccessKeyEntry.GroupOwnerPublicKey[:]) ||
			!EqualGroupKeyName(accessKeyEntry.AccessGroupKeyName, prevAccessKeyEntry.AccessGroupKeyName) {

			return fmt.Errorf("_disconnectBasicTransfer: Error, this key was already deleted "+
				"accessKey: %v", accessKey)
		}
	}

	// Delete this item from UtxoView to indicate we should remove this entry from DB.
	bav._deleteAccessGroupKeyToAccessGroupEntryMapping(&accessKey.OwnerPublicKey, accessKeyEntry)
	// If the previous entry exists, we should set it in the utxoview
	if prevAccessKeyEntry != nil {
		bav._setAccessGroupKeyToAccessGroupEntryMapping(&accessKey.OwnerPublicKey, prevAccessKeyEntry)
	}

	// Now disconnect the basic transfer.
	return bav._disconnectBasicTransfer(
		currentTxn, txnHash, utxoOpsForTxn[:operationIndex], blockHeight)
}
