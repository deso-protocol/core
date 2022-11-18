package lib

import (
	"github.com/dgraph-io/badger/v3"
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

func (adapter *DbAdapter) GetUserAssociationsByAttributes(associationQuery *UserAssociationQuery) ([]*UserAssociationEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetUserAssociationsByAttributes(associationQuery)
	}
	return DBGetUserAssociationsByAttributes(adapter.badgerDb, adapter.snapshot, associationQuery)
}

func (adapter *DbAdapter) GetPostAssociationsByAttributes(associationQuery *PostAssociationQuery) ([]*PostAssociationEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetPostAssociationsByAttributes(associationQuery)
	}
	return DBGetPostAssociationsByAttributes(adapter.badgerDb, adapter.snapshot, associationQuery)
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
