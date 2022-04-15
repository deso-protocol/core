package lib

import (
	"github.com/dgraph-io/badger/v3"
)

type DbAdapter struct {
	badgerDb   *badger.DB
	postgresDb *Postgres
}

func (bav *UtxoView) GetDbAdapter() *DbAdapter {
	return &DbAdapter{
		badgerDb:   bav.Handle,
		postgresDb: bav.Postgres,
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

	return DbGetBalanceEntry(adapter.badgerDb, holder, creator, isDAOCoin)
}

//
// DAO coin limit order
//

func (adapter *DbAdapter) GetDAOCoinLimitOrder(orderID *BlockHash) (*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetDAOCoinLimitOrder(orderID)
	}

	return DBGetDAOCoinLimitOrder(adapter.badgerDb, orderID)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrders() ([]*DAOCoinLimitOrderEntry, error) {
	// This function is currently used for testing purposes only.
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAllDAOCoinLimitOrders()
	}

	return DBGetAllDAOCoinLimitOrders(adapter.badgerDb)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingDAOCoinCreatorPKID *PKID, sellingDAOCoinCreatorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
	}

	return DBGetAllDAOCoinLimitOrdersForThisDAOCoinPair(adapter.badgerDb, buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	}

	return DBGetAllDAOCoinLimitOrdersForThisTransactor(adapter.badgerDb, transactorPKID)
}

func (adapter *DbAdapter) GetMatchingDAOCoinLimitOrders(inputOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetMatchingDAOCoinLimitOrders(inputOrder, lastSeenOrder)
	}

	var outputOrders []*DAOCoinLimitOrderEntry
	var err error

	err = adapter.badgerDb.View(func(txn *badger.Txn) error {
		outputOrders, err = DBGetMatchingDAOCoinLimitOrders(txn, inputOrder, lastSeenOrder)
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

	return DBGetPKIDEntryForPublicKey(adapter.badgerDb, pkBytes).PKID
}
