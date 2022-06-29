package lib

import (
	"github.com/dgraph-io/badger/v3"
)

type DbAdapter struct {
	badgerDb   *badger.DB
	postgresDb *Postgres
	snapshot   *Snapshot
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
