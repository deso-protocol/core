package lib

import (
	"github.com/dgraph-io/badger/v3"
)

type DbAdapter struct {
	badgerDb   *badger.DB
	postgresDb *Postgres
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

func (adapter *DbAdapter) GetDAOCoinLimitOrder(orderEntry *DAOCoinLimitOrderEntry) (*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetDAOCoinLimitOrder(orderEntry)
	}

	return DBGetDAOCoinLimitOrder(adapter.badgerDb, orderEntry)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrders() ([]*DAOCoinLimitOrderEntry, error) {
	// This function is currently used for testing purposes only.
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAllDAOCoinLimitOrders()
	}

	return DBGetAllDAOCoinLimitOrders(adapter.badgerDb)
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingDAOCoinCreatorPKID *PKID, sellingDAOCoinCreatorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	var orders []*DAOCoinLimitOrderEntry
	var err error

	if adapter.postgresDb != nil {
		orders, err = adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisDAOCoinPair(buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
	} else {
		orders, err = DBGetAllDAOCoinLimitOrdersForThisDAOCoinPair(adapter.badgerDb, buyingDAOCoinCreatorPKID, sellingDAOCoinCreatorPKID)
	}

	if err != nil {
		return nil, err
	}

	return orders, nil
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID *PKID) ([]*DAOCoinLimitOrderEntry, error) {
	var orders []*DAOCoinLimitOrderEntry
	var err error

	if adapter.postgresDb != nil {
		orders, err = adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisTransactor(transactorPKID)
	} else {
		orders, err = DBGetAllDAOCoinLimitOrdersForThisTransactor(adapter.badgerDb, transactorPKID)
	}

	if err != nil {
		return nil, err
	}

	return orders, nil
}

func (adapter *DbAdapter) GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(inputOrder *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(inputOrder)
	}

	return DBGetAllDAOCoinLimitOrdersForThisTransactorAtThisPrice(adapter.badgerDb, inputOrder)
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
