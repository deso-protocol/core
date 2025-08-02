package lib

import (
	"github.com/dgraph-io/badger/v3"
)

// _syncerSinceKey returns the static DB key used to persist the "since"
// cursor.  Keeping it behind a helper mirrors the convention used by other
// components when they evolve from a simple constant prefix to something that
// might incorporate additional bytes in the future.
func _syncerSinceKey() []byte {
	return Prefixes.PrefixStateSyncerSince
}

// getLastSince fetches the most recent Badger backup cursor.  Zero is returned
// if the key does not exist (e.g. first run).
func (stateChangeSyncer *StateChangeSyncer) getLastSince(db *badger.DB) (uint64, error) {
	var since uint64
	var retErr error

	db.View(func(txn *badger.Txn) error {
		valBytes, err := DBGetWithTxn(txn, nil, _syncerSinceKey())
		if err == badger.ErrKeyNotFound {
			since = 0
			return nil
		} else if err != nil {
			retErr = err
			return err
		}
		since = DecodeUint64(valBytes)
		return nil
	})

	return since, retErr
}

// setLastSince persists the provided Badger timestamp so that the next diff
// generation stream starts from this point.
func (stateChangeSyncer *StateChangeSyncer) setLastSince(db *badger.DB, ts uint64) error {
	return db.Update(func(txn *badger.Txn) error {
		return DBSetWithTxn(txn, nil, _syncerSinceKey(), EncodeUint64(ts), nil)
	})
}
