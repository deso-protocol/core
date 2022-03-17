package lib

import "github.com/dgraph-io/badger/v3"

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
		} else {
			return adapter.postgresDb.GetCreatorCoinBalance(holder, creator).NewBalanceEntry()
		}
	} else {
		return DbGetBalanceEntry(adapter.badgerDb, holder, creator, isDAOCoin)
	}
}

//
// DAO coin limit order
//

func (adapter *DbAdapter) GetDAOCoinLimitOrder(orderEntry *DAOCoinLimitOrderEntry, byTransactorPKID bool) *DAOCoinLimitOrderEntry {
	if adapter.postgresDb != nil {
		return adapter.postgresDb.GetDAOCoinLimitOrder(orderEntry)
	} else {
		return DBGetDAOCoinLimitOrder(adapter.badgerDb, orderEntry, byTransactorPKID)
	}
}
