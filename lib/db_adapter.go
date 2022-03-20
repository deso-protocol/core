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

func (adapter *DbAdapter) GetDAOCoinLimitOrder(orderEntry *DAOCoinLimitOrderEntry, byTransactorPKID bool) *DAOCoinLimitOrderEntry {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetDAOCoinLimitOrder(orderEntry)
	}

	return DBGetDAOCoinLimitOrder(adapter.badgerDb, orderEntry, byTransactorPKID)
}

// This function is currently used for testing purposes only.
func (adapter *DbAdapter) GetAllDAOCoinLimitOrders() ([]*DAOCoinLimitOrderEntry, error) {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetAllDAOCoinLimitOrders()
	}

	return DBGetAllDAOCoinLimitOrders(adapter.badgerDb)
}

func (adapter *DbAdapter) GetMatchingDAOCoinLimitOrders(transactorOrder *DAOCoinLimitOrderEntry, lastSeenOrder *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error) {
	var outputOrders []*DAOCoinLimitOrderEntry
	var err error

	if adapter.postgresDb != nil {
		var postgresFunc func(*DAOCoinLimitOrderEntry, *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error)

		if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
			postgresFunc = adapter.postgresDb.GetMatchingDAOCoinBidOrders
		} else if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
			postgresFunc = adapter.postgresDb.GetMatchingDAOCoinAskOrders
		} else {
			return nil, RuleErrorDAOCoinLimitOrderUnsupportedOperationType
		}

		outputOrders, err = postgresFunc(transactorOrder, lastSeenOrder)
	} else {
		err = adapter.badgerDb.View(func(txn *badger.Txn) error {
			var badgerFunc func(*badger.Txn, *DAOCoinLimitOrderEntry, *DAOCoinLimitOrderEntry) ([]*DAOCoinLimitOrderEntry, error)

			if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeAsk {
				badgerFunc = DBGetMatchingDAOCoinBidOrders
			} else if transactorOrder.OperationType == DAOCoinLimitOrderEntryOrderTypeBid {
				badgerFunc = DBGetMatchingDAOCoinAskOrders
			} else {
				return RuleErrorDAOCoinLimitOrderUnsupportedOperationType
			}

			outputOrders, err = badgerFunc(txn, transactorOrder, lastSeenOrder)
			return err
		})
	}

	return outputOrders, err
}
