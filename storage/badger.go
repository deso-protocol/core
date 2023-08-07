package storage

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/pkg/errors"
	"os"
)

const (
	// PerformanceMemTableSize is 3072 MB. Increases the maximum
	// amount of data we can commit in a single transaction.
	PerformanceMemTableSize = 3072 << 20

	// PerformanceLogValueSize is 256 MB.
	PerformanceLogValueSize = 256 << 20
)

type BadgerDatabase struct {
	db            *badger.DB
	opts          badger.Options
	useWriteBatch bool
}

func NewBadgerDatabase(opts badger.Options, useWriteBatch bool) *BadgerDatabase {
	return &BadgerDatabase{
		db:            nil,
		opts:          opts,
		useWriteBatch: useWriteBatch,
	}
}

func (bdb *BadgerDatabase) Setup() error {
	db, err := badger.Open(bdb.opts)
	if err != nil {
		return errors.Wrapf(err, "Setup:")
	}
	bdb.db = db
	return nil
}

func (bdb *BadgerDatabase) Update(fn func(Transaction) error) error {
	var wb *badger.WriteBatch
	if bdb.useWriteBatch {
		wb = bdb.db.NewWriteBatch()
	}

	err := bdb.db.Update(func(txn *badger.Txn) error {
		T := NewBadgerTransaction(txn, wb)
		return fn(T)
	})
	if err != nil {
		return errors.Wrapf(err, "Update:")
	}

	if bdb.useWriteBatch {
		err = wb.Flush()
		if err != nil {
			return errors.Wrapf(err, "Update: Problem flushing write batch")
		}
		wb.Cancel()
	}
	return nil
}

func (bdb *BadgerDatabase) View(fn func(Transaction) error) error {
	return bdb.db.View(func(txn *badger.Txn) error {
		T := NewBadgerTransaction(txn, nil)
		return fn(T)
	})
}

func (bdb *BadgerDatabase) Close() error {
	return bdb.db.Close()
}

func (bdb *BadgerDatabase) Erase() error {
	return os.RemoveAll(bdb.opts.Dir)
}

// ==========================
// BadgerTransaction
// ==========================

type BadgerTransaction struct {
	txn *badger.Txn
	wb  *badger.WriteBatch
}

func NewBadgerTransaction(txn *badger.Txn, wb *badger.WriteBatch) *BadgerTransaction {
	return &BadgerTransaction{
		txn: txn,
		wb:  wb,
	}
}

func (btx *BadgerTransaction) Set(key []byte, value []byte) error {
	if btx.wb != nil {
		return btx.wb.Set(key, value)
	}
	return btx.txn.Set(key, value)
}

func (btx *BadgerTransaction) Delete(key []byte) error {
	if btx.wb != nil {
		return btx.wb.Delete(key)
	}
	return btx.txn.Delete(key)
}

func (btx *BadgerTransaction) Get(key []byte) ([]byte, error) {
	var value []byte

	item, err := btx.txn.Get(key)
	if err != nil {
		return value, errors.Wrapf(err, "Get:")
	}
	return item.ValueCopy(nil)
}

func (btx *BadgerTransaction) GetIterator(prefix []byte) (Iterator, error) {
	opts := badger.DefaultIteratorOptions
	it := btx.txn.NewIterator(opts)
	it.Seek(prefix)
	return NewBadgerIterator(it, prefix), nil
}

// ==========================
// BadgerIterator
// ==========================

type BadgerIterator struct {
	it          *badger.Iterator
	prefix      []byte
	initialized bool
}

func NewBadgerIterator(it *badger.Iterator, prefix []byte) *BadgerIterator {
	return &BadgerIterator{
		it:          it,
		prefix:      prefix,
		initialized: false,
	}
}

func (bit *BadgerIterator) Value() ([]byte, error) {
	item := bit.it.Item()
	return item.ValueCopy(nil)
}

func (bit *BadgerIterator) Key() []byte {
	return bit.it.Item().KeyCopy(nil)
}

func (bit *BadgerIterator) Next() bool {
	if !bit.initialized {
		bit.initialized = true
		return bit.it.Valid()
	}

	bit.it.Next()
	return bit.it.ValidForPrefix(bit.prefix)
}

func (bit *BadgerIterator) Close() {
	bit.it.Close()
}

// PerformanceBadgerOptions are performance geared
// BadgerDB options that use much more RAM than the
// default settings.
func PerformanceBadgerOptions(dir string) badger.Options {
	opts := badger.DefaultOptions(dir)

	// Use an extended table size for larger commits.
	opts.MemTableSize = PerformanceMemTableSize
	opts.ValueLogFileSize = PerformanceLogValueSize

	return opts
}

func DefaultBadgerOptions(dir string) badger.Options {
	opts := badger.DefaultOptions(dir)

	opts.Logger = nil
	return opts
}
