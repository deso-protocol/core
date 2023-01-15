package lib

import (
	"bytes"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"sort"
)

type DbAdapter struct {
	badgerDb   *badger.DB
	postgresDb *Postgres
	snapshot   *Snapshot
}

func (bc *Blockchain) NewDbAdapter() *DbAdapter {
	return &DbAdapter{
		badgerDb:   bc.db,
		postgresDb: bc.postgres,
		snapshot:   bc.snapshot,
	}
}

func (bav *UtxoView) GetDbAdapter() *DbAdapter {
	snap := bav.Snapshot
	if bav.Postgres != nil {
		snap = nil
	}
	return &DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
		snapshot:   snap,
	}
}

//
// Associations
//

func (adapter *DbAdapter) GetUserAssociationByID(associationID *BlockHash) (*UserAssociationEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetUserAssociationByID(associationID)
	}
	return DBGetUserAssociationByID(adapter.badgerDb, adapter.snapshot, associationID)
}

func (adapter *DbAdapter) GetPostAssociationByID(associationID *BlockHash) (*PostAssociationEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPostAssociationByID(associationID)
	}
	return DBGetPostAssociationByID(adapter.badgerDb, adapter.snapshot, associationID)
}

func (adapter *DbAdapter) GetUserAssociationByAttributes(associationEntry *UserAssociationEntry) (*UserAssociationEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetUserAssociationByAttributes(associationEntry)
	}
	return DBGetUserAssociationByAttributes(adapter.badgerDb, adapter.snapshot, associationEntry)
}

func (adapter *DbAdapter) GetPostAssociationByAttributes(associationEntry *PostAssociationEntry) (*PostAssociationEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPostAssociationByAttributes(associationEntry)
	}
	return DBGetPostAssociationByAttributes(adapter.badgerDb, adapter.snapshot, associationEntry)
}

func (adapter *DbAdapter) GetUserAssociationsByAttributes(
	associationQuery *UserAssociationQuery, utxoViewAssociationIds *Set[BlockHash],
) ([]*UserAssociationEntry, []byte, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetUserAssociationsByAttributes(associationQuery, utxoViewAssociationIds)
	}
	return DBGetUserAssociationsByAttributes(adapter.badgerDb, adapter.snapshot, associationQuery, utxoViewAssociationIds)
}

func (adapter *DbAdapter) GetPostAssociationsByAttributes(
	associationQuery *PostAssociationQuery, utxoViewAssociationIds *Set[BlockHash],
) ([]*PostAssociationEntry, []byte, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPostAssociationsByAttributes(associationQuery, utxoViewAssociationIds)
	}
	return DBGetPostAssociationsByAttributes(adapter.badgerDb, adapter.snapshot, associationQuery, utxoViewAssociationIds)
}

func (adapter *DbAdapter) GetUserAssociationIdsByAttributes(
	associationQuery *UserAssociationQuery, utxoViewAssociationIds *Set[BlockHash],
) (*Set[BlockHash], []byte, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetUserAssociationIdsByAttributes(associationQuery, utxoViewAssociationIds)
	}
	return DBGetUserAssociationIdsByAttributes(adapter.badgerDb, adapter.snapshot, associationQuery, utxoViewAssociationIds)
}

func (adapter *DbAdapter) GetPostAssociationIdsByAttributes(
	associationQuery *PostAssociationQuery, utxoViewAssociationIds *Set[BlockHash],
) (*Set[BlockHash], []byte, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPostAssociationIdsByAttributes(associationQuery, utxoViewAssociationIds)
	}
	return DBGetPostAssociationIdsByAttributes(adapter.badgerDb, adapter.snapshot, associationQuery, utxoViewAssociationIds)
}

func (adapter *DbAdapter) SortUserAssociationEntriesByPrefix(
	associationEntries []*UserAssociationEntry,
	prefixType []byte,
	sortDescending bool,
) ([]*UserAssociationEntry, error) {
	// Postgres sorts results by AssociationID.
	if adapter.postgresDb != nil {
		sort.Slice(associationEntries, func(ii int, jj int) bool {
			byteComparison := bytes.Compare(
				associationEntries[ii].AssociationID.ToBytes(),
				associationEntries[jj].AssociationID.ToBytes(),
			)
			if sortDescending {
				return byteComparison > 0
			}
			return byteComparison <= 0
		})
		return associationEntries, nil
	}

	// Badger sorts results by the key prefix.
	var innerErr error
	sort.Slice(associationEntries, func(ii int, jj int) bool {
		keyII, err := DBKeyForUserAssociationByPrefix(associationEntries[ii], prefixType)
		if err != nil {
			innerErr = err
			return false
		}
		keyJJ, err := DBKeyForUserAssociationByPrefix(associationEntries[jj], prefixType)
		if err != nil {
			innerErr = err
			return false
		}
		byteComparison := bytes.Compare(keyII, keyJJ)
		if sortDescending {
			return byteComparison > 0
		}
		return byteComparison <= 0
	})
	if innerErr != nil {
		return nil, errors.Wrapf(innerErr, "SortUserAssociationEntriesByPrefix: ")
	}
	return associationEntries, nil
}

func (adapter *DbAdapter) SortPostAssociationEntriesByPrefix(
	associationEntries []*PostAssociationEntry,
	prefixType []byte,
	sortDescending bool,
) ([]*PostAssociationEntry, error) {
	// Postgres sorts results by AssociationID.
	if adapter.postgresDb != nil {
		sort.Slice(associationEntries, func(ii int, jj int) bool {
			byteComparison := bytes.Compare(
				associationEntries[ii].AssociationID.ToBytes(),
				associationEntries[jj].AssociationID.ToBytes(),
			)
			if sortDescending {
				return byteComparison > 0
			}
			return byteComparison <= 0
		})
		return associationEntries, nil
	}

	// Badger sorts results by the key prefix.
	var innerErr error
	sort.Slice(associationEntries, func(ii int, jj int) bool {
		keyII, err := DBKeyForPostAssociationByPrefix(associationEntries[ii], prefixType)
		if err != nil {
			innerErr = err
			return false
		}
		keyJJ, err := DBKeyForPostAssociationByPrefix(associationEntries[jj], prefixType)
		if err != nil {
			innerErr = err
			return false
		}
		byteComparison := bytes.Compare(keyII, keyJJ)
		if sortDescending {
			return byteComparison > 0
		}
		return byteComparison <= 0
	})
	if innerErr != nil {
		return nil, errors.Wrapf(innerErr, "SortPostAssociationEntriesByPrefix: ")
	}
	return associationEntries, nil
}

//
// Balance entry
//

func (adapter *DbAdapter) GetBalanceEntry(holder *PKID, creator *PKID, isDAOCoin bool) *BalanceEntry {
	if adapter.postgresDb != nil {
		if isDAOCoin {
			return adapter.postgresDb.GetDAOCoinBalance(holder, creator).NewBalanceEntry()
		}

		return adapter.postgresDb.GetCreatorCoinBalance(holder, creator).NewBalanceEntry()
	}

	return DbGetBalanceEntry(adapter.badgerDb, adapter.snapshot, holder, creator, isDAOCoin)
}

//
// Derived keys
//

func (adapter *DbAdapter) GetOwnerToDerivedKeyMapping(ownerPublicKey PublicKey, derivedPublicKey PublicKey) *DerivedKeyEntry {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetDerivedKey(&ownerPublicKey, &derivedPublicKey).NewDerivedKeyEntry()
	}

	return DBGetOwnerToDerivedKeyMapping(adapter.badgerDb, adapter.snapshot, ownerPublicKey, derivedPublicKey)
}

//
// DAO coin limit order
//

func (adapter *DbAdapter) GetDAOCoinLimitOrder(orderID *BlockHash) (*DAOCoinLimitOrderEntry, error) {
	// Temporarily use badger to support DAO Coin limit order DB operations
	//if adapter.postgresDb != nil {
	//	return adapter.postgresDb.GetDAOCoinLimitOrder(orderID)
	//}

	return DBGetDAOCoinLimitOrder(adapter.badgerDb, adapter.snapshot, orderID)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrders() ([]*DAOCoinLimitOrderEntry, error) {
	// This function is currently used for testing purposes only.
	// Temporarily use badger to support DAO Coin limit order DB operations
	//if adapter.postgresDb != nil {
	//	return adapter.postgresDb.GetAllDAOCoinLimitOrders()
	//}

	return DBGetAllDAOCoinLimitOrders(adapter.badgerDb)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingDAOCoinCreatorPKID *PKID, sellingDAOCoinCreatorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	// Temporarily use badger to support DAO Coin limit order DB operations
	//if adapter.postgresDb != nil {
	//	return adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
	//}

	return DBGetAllDAOCoinLimitOrdersForThisDAOCoinPair(adapter.badgerDb, buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	// Temporarily use badger to support DAO Coin limit order DB operations
	//if adapter.postgresDb != nil {
	//	return adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	//}

	return DBGetAllDAOCoinLimitOrdersForThisTransactor(adapter.badgerDb, transactorPKID)
}

func (adapter *DbAdapter) GetMatchingDAOCoinLimitOrders(inputOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry, orderEntriesInView map[DAOCoinLimitOrderMapKey]bool) ([]*DAOCoinLimitOrderEntry, error) {
	// Temporarily use badger to support DAO Coin limit order DB operations
	//if adapter.postgresDb != nil {
	//	return adapter.postgresDb.GetMatchingDAOCoinLimitOrders(inputOrder, lastSeenOrder, orderEntriesInView)
	//}

	var outputOrders []*DAOCoinLimitOrderEntry
	var err error

	err = adapter.badgerDb.View(func(txn *badger.Txn) error {
		outputOrders, err = DBGetMatchingDAOCoinLimitOrders(txn, inputOrder, lastSeenOrder, orderEntriesInView)
		return err
	})

	return outputOrders, err
}

//
// PKID
//

func (adapter *DbAdapter) GetPKIDForPublicKey(pkBytes []byte) *PKID {
	if adapter.postgresDb != nil {
		profile := adapter.postgresDb.GetProfileForPublicKey(pkBytes)
		if profile == nil {
			return NewPKID(pkBytes)
		}
		return profile.PKID
	}

	return DBGetPKIDEntryForPublicKey(adapter.badgerDb, adapter.snapshot, pkBytes).PKID
}

//
// AccessGroups
//

func (adapter *DbAdapter) GetAccessGroupEntryByAccessGroupId(accessGroupId *AccessGroupId) (*AccessGroupEntry, error) {
	if accessGroupId == nil {
		glog.Errorf("GetAccessGroupEntryByAccessGroupId: Called with nil accessGroupId, this should never happen")
		return nil, nil
	}

	if adapter.postgresDb != nil {
		pgAccessGroup := adapter.postgresDb.GetAccessGroupByAccessGroupId(accessGroupId)
		if pgAccessGroup == nil {
			return nil, nil
		}
		return pgAccessGroup.ToAccessGroupEntry(), nil
	} else {
		return DBGetAccessGroupEntryByAccessGroupId(adapter.badgerDb, adapter.snapshot,
			&accessGroupId.AccessGroupOwnerPublicKey, &accessGroupId.AccessGroupKeyName)
	}
}

func (adapter *DbAdapter) GetAccessGroupExistenceByAccessGroupId(accessGroupId *AccessGroupId) (bool, error) {
	if accessGroupId == nil {
		glog.Errorf("GetAccessGroupExistenceByAccessGroupId: Called with nil accessGroupId, this should never happen")
		return false, nil
	}

	if adapter.postgresDb != nil {
		pgAccessGroup := adapter.postgresDb.GetAccessGroupByAccessGroupId(accessGroupId)
		if pgAccessGroup == nil {
			return false, nil
		}
		return true, nil
	} else {
		return DBGetAccessGroupExistenceByAccessGroupId(adapter.badgerDb, adapter.snapshot,
			&accessGroupId.AccessGroupOwnerPublicKey, &accessGroupId.AccessGroupKeyName)
	}
}

func (adapter *DbAdapter) GetAccessGroupIdsForOwner(ownerPublicKey *PublicKey) (_accessGroupIdsOwned []*AccessGroupId, _err error) {
	var accessGroupIds []*AccessGroupId
	var err error
	if ownerPublicKey == nil {
		glog.Errorf("GetAccessGroupEntriesForOwner: Called with nil ownerPublicKey, this should never happen")
		return nil, nil
	}

	if adapter.postgresDb != nil {
		pgAccessGroupEntries := adapter.postgresDb.GetAccessGroupEntriesForOwner(*ownerPublicKey)
		if pgAccessGroupEntries == nil {
			return nil, nil
		}
		for _, pgAccessGroupEntry := range pgAccessGroupEntries {
			accessGroupEntry := pgAccessGroupEntry.ToAccessGroupEntry()
			accessGroupId := NewAccessGroupId(ownerPublicKey, accessGroupEntry.AccessGroupKeyName.ToBytes())
			accessGroupIds = append(accessGroupIds, accessGroupId)
		}
	} else {
		accessGroupIds, err = DBGetAccessGroupIdsForOwner(adapter.badgerDb, adapter.snapshot, *ownerPublicKey)
		if err != nil {
			return nil, err
		}
	}
	return accessGroupIds, nil
}

func (adapter *DbAdapter) GetAccessGroupIdsForMember(memberPublicKey *PublicKey) (_accessGroupIdsMember []*AccessGroupId, _err error) {
	var accessGroupIds []*AccessGroupId
	var err error

	if memberPublicKey == nil {
		glog.Errorf("GetAccessGroupEntriesForMember: Called with nil memberPublicKey, this should never happen")
		return nil, nil
	}

	if adapter.postgresDb != nil {
		pgAccessGroupEnumerationEntries, err := adapter.postgresDb.GetAccessGroupEnumerationEntriesForMember(*memberPublicKey)
		if err != nil {
			return nil, err
		}
		for _, pgAccessEnumerationEntry := range pgAccessGroupEnumerationEntries {
			accessGroupId := NewAccessGroupId(
				pgAccessEnumerationEntry.AccessGroupOwnerPublicKey, pgAccessEnumerationEntry.AccessGroupKeyName.ToBytes())
			accessGroupIds = append(accessGroupIds, accessGroupId)
		}
	} else {
		accessGroupIds, err = DBGetAccessGroupIdsForMember(adapter.badgerDb, adapter.snapshot, *memberPublicKey)
		if err != nil {
			return nil, err
		}
	}

	return accessGroupIds, nil
}

//
// AccessGroupMembers
//

func (adapter *DbAdapter) GetAccessGroupMemberEntry(accessGroupMemberPublicKey PublicKey,
	accessGroupOwnerPublicKey PublicKey, accessGroupKeyName GroupKeyName) (*AccessGroupMemberEntry, error) {

	if adapter.postgresDb != nil {
		pgAccessGroupMember := adapter.postgresDb.GetAccessGroupMemberEntry(accessGroupMemberPublicKey,
			accessGroupOwnerPublicKey, accessGroupKeyName)
		if pgAccessGroupMember == nil {
			return nil, nil
		}
		_, _, accessGroupMember := pgAccessGroupMember.ToAccessGroupMemberEntry()
		return accessGroupMember, nil
	} else {
		return DBGetAccessGroupMemberEntry(adapter.badgerDb, adapter.snapshot,
			accessGroupMemberPublicKey, accessGroupOwnerPublicKey, accessGroupKeyName)
	}
}

func (adapter *DbAdapter) GetAccessGroupMemberEnumerationEntry(accessGroupMemberPublicKey PublicKey,
	accessGroupOwnerPublicKey PublicKey, accessGroupKeyName GroupKeyName) (_exists bool, _err error) {

	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAccessGroupMemberEnumerationEntry(accessGroupMemberPublicKey,
			accessGroupOwnerPublicKey, accessGroupKeyName), nil
	} else {
		// TODO: Use similar function signatures.
		return DBGetAccessGroupMemberExistenceFromEnumerationIndex(adapter.badgerDb, adapter.snapshot,
			accessGroupMemberPublicKey, accessGroupOwnerPublicKey, accessGroupKeyName)
	}
}

func (adapter *DbAdapter) GetPaginatedAccessGroupMembersEnumerationEntries(
	accessGroupOwnerPublicKey PublicKey, accessGroupKeyName GroupKeyName,
	startingAccessGroupMemberPublicKeyBytes []byte, maxMembersToFetch uint32) (
	_accessGroupMemberPublicKeys []*PublicKey, _err error) {

	if maxMembersToFetch == 0 {
		return nil, nil
	}

	if adapter.postgresDb != nil {
		// TODO: This might fail if keys don't exist, but it shouldn't.
		return adapter.postgresDb.GetPaginatedAccessGroupMembersFromEnumerationIndex(
			accessGroupOwnerPublicKey, accessGroupKeyName,
			startingAccessGroupMemberPublicKeyBytes, maxMembersToFetch)
	} else {
		return DBGetPaginatedAccessGroupMembersFromEnumerationIndex(adapter.badgerDb, adapter.snapshot,
			accessGroupOwnerPublicKey, accessGroupKeyName,
			startingAccessGroupMemberPublicKeyBytes, maxMembersToFetch)
	}
}

//
// NewMessage
//

func (adapter *DbAdapter) GetDmMessageEntry(dmMessageKey DmMessageKey) (*NewMessageEntry, error) {

	if adapter.postgresDb != nil {
		pgDmMessage := adapter.postgresDb.GetNewMessageDmEntry(dmMessageKey)
		if pgDmMessage == nil {
			return nil, nil
		}
		dmMessage := pgDmMessage.ToNewMessageEntry()
		return dmMessage, nil
	} else {
		return DBGetDmMessageEntry(adapter.badgerDb, adapter.snapshot, dmMessageKey)
	}
}

func (adapter *DbAdapter) GetGroupChatMessageEntry(groupChatMessageKey GroupChatMessageKey) (*NewMessageEntry, error) {

	if adapter.postgresDb != nil {
		pgGroupChatMessage := adapter.postgresDb.GetNewMessageGroupChatEntry(groupChatMessageKey)
		if pgGroupChatMessage == nil {
			return nil, nil
		}
		groupChatMessage := pgGroupChatMessage.ToNewMessageEntry()
		return groupChatMessage, nil
	} else {
		return DBGetGroupChatMessageEntry(adapter.badgerDb, adapter.snapshot, groupChatMessageKey)
	}
}

func (adapter *DbAdapter) CheckDmThreadExistence(dmThreadKey DmThreadKey) (*DmThreadExistence, error) {

	if adapter.postgresDb != nil {
		pgDmThreadExistence := adapter.postgresDb.CheckDmThreadExistence(dmThreadKey)
		if pgDmThreadExistence == nil {
			return nil, nil
		}
		return pgDmThreadExistence, nil
	} else {
		return DBCheckDmThreadExistence(adapter.badgerDb, adapter.snapshot, dmThreadKey)
	}
}

func (adapter *DbAdapter) CheckGroupChatThreadExistence(groupKey AccessGroupId) (*GroupChatThreadExistence, error) {

	if adapter.postgresDb != nil {
		pgGroupChatThreadExistence := adapter.postgresDb.CheckGroupChatThreadExistence(groupKey)
		if pgGroupChatThreadExistence == nil {
			return nil, nil
		}
		return pgGroupChatThreadExistence, nil
	} else {
		return DBCheckGroupChatThreadExistence(adapter.badgerDb, adapter.snapshot, groupKey)
	}
}

func (adapter *DbAdapter) GetAllUserDmThreads(userAccessGroupOwnerPublicKey PublicKey) (
	_dmThreadKeys []*DmThreadKey, _err error) {

	if adapter.postgresDb != nil {
		// TODO: The error might be thrown when key doesnt exist
		return adapter.postgresDb.GetAllUserDmThreads(userAccessGroupOwnerPublicKey)
	} else {
		return DBGetAllUserDmThreads(adapter.badgerDb, adapter.snapshot, userAccessGroupOwnerPublicKey)
	}
}

func (adapter *DbAdapter) GetPaginatedMessageEntriesForDmThread(dmThreadKey DmThreadKey, startingTimestamp uint64,
	maxMessagesToFetch uint64) (_messageEntries []*NewMessageEntry, _err error) {

	if maxMessagesToFetch == 0 {
		return nil, nil
	}

	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPaginatedMessageEntriesForDmThread(
			dmThreadKey, startingTimestamp, maxMessagesToFetch)
	} else {
		return DBGetPaginatedDmMessageEntry(adapter.badgerDb, adapter.snapshot,
			dmThreadKey, startingTimestamp, maxMessagesToFetch)
	}
}

func (adapter *DbAdapter) GetPaginatedMessageEntriesForGroupChatThread(groupChatThread AccessGroupId, startingTimestamp uint64,
	maxMessagesToFetch uint64) (_messageEntries []*NewMessageEntry, _err error) {

	if maxMessagesToFetch == 0 {
		return nil, nil
	}

	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPaginatedMessageEntriesForGroupChatThread(
			groupChatThread, startingTimestamp, maxMessagesToFetch)
	} else {
		return DBGetPaginatedGroupChatMessageEntry(adapter.badgerDb, adapter.snapshot,
			groupChatThread, startingTimestamp, maxMessagesToFetch)
	}
}

func (adapter *DbAdapter) GetThreadAttributesEntry(threadKey ThreadAttributesKey) (*ThreadAttributesEntry, error) {

	if adapter.postgresDb != nil {
		pgThreadAttributesEntry := adapter.postgresDb.GetThreadAttributesEntry(threadKey)
		if pgThreadAttributesEntry == nil {
			return nil, nil
		}
		_, threadAttributesEntry := pgThreadAttributesEntry.ToThreadAttributesKeyAndThreadAttributesEntry()
		return threadAttributesEntry, nil
	} else {
		return DBGetThreadAttributesEntry(adapter.badgerDb, adapter.snapshot, threadKey)
	}
}
