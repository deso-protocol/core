package lib

import (
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
)

type encoderPrefixProgress struct {
	prefix  []byte
	lastKey []byte
}

type EncoderMigration struct {
	outstandingPrefixes []*encoderPrefixProgress

	db        *badger.DB
	chainLock *deadlock.RWMutex
}

func (migration *EncoderMigration) Initialize(db *badger.DB, chainLock *deadlock.RWMutex) {
	migration.db = db
	migration.chainLock = chainLock

}
