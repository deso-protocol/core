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

func (bdb *BadgerDatabase) GetContext(id []byte) Context {
	return NewBadgerContext(id, bdb.useWriteBatch)
}

func (bdb *BadgerDatabase) Update(ctx Context, fn func(Transaction, Context) error) error {
	var wb *badger.WriteBatch
	if bdb.useWriteBatch {
		wb = bdb.db.NewWriteBatch()
	}

	err := bdb.db.Update(func(txn *badger.Txn) error {
		T := NewBadgerTransaction(txn, wb)
		return fn(T, ctx)
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

func (bdb *BadgerDatabase) View(ctx Context, fn func(Transaction, Context) error) error {
	return bdb.db.View(func(txn *badger.Txn) error {
		T := NewBadgerTransaction(txn, nil)
		return fn(T, ctx)
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

func (btx *BadgerTransaction) Set(key []byte, value []byte, ctx Context) error {
	prefixedKey, err := castBadgerContextAndGetPrefixedKey(key, ctx)
	if err != nil {
		return errors.Wrapf(err, "Set:")
	}

	if btx.wb != nil {
		return btx.wb.Set(prefixedKey, value)
	}
	return btx.txn.Set(prefixedKey, value)
}

func (btx *BadgerTransaction) Delete(key []byte, ctx Context) error {
	prefixedKey, err := castBadgerContextAndGetPrefixedKey(key, ctx)
	if err != nil {
		return errors.Wrapf(err, "Delete:")
	}

	if btx.wb != nil {
		return btx.wb.Delete(prefixedKey)
	}
	return btx.txn.Delete(prefixedKey)
}

func (btx *BadgerTransaction) Get(key []byte, ctx Context) ([]byte, error) {
	var value []byte
	prefixedKey, err := castBadgerContextAndGetPrefixedKey(key, ctx)
	if err != nil {
		return nil, errors.Wrapf(err, "Get:")
	}

	item, err := btx.txn.Get(prefixedKey)
	if err != nil {
		return value, errors.Wrapf(err, "Get:")
	}
	return item.ValueCopy(nil)
}

func (btx *BadgerTransaction) GetIterator(ctx Context) (Iterator, error) {
	badgerCtx, err := AssertContext[*BadgerContext](ctx, BADGERDB)
	if err != nil {
		return nil, err
	}
	opts := badger.DefaultIteratorOptions
	it := btx.txn.NewIterator(opts)
	it.Seek(badgerCtx.prefix)
	return NewBadgerIterator(it, badgerCtx), nil
}

// ==========================
// BadgerIterator
// ==========================

type BadgerIterator struct {
	it          *badger.Iterator
	ctx         *BadgerContext
	initialized bool
}

func NewBadgerIterator(it *badger.Iterator, ctx *BadgerContext) *BadgerIterator {
	return &BadgerIterator{
		it:          it,
		ctx:         ctx,
		initialized: false,
	}
}

func (bit *BadgerIterator) GetContext() Context {
	return bit.ctx
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
	return bit.it.ValidForPrefix(bit.ctx.prefix)
}

func (bit *BadgerIterator) Close() {
	bit.it.Close()
}

// ==========================
// BadgerContext
// ==========================

type BadgerContext struct {
	prefix        []byte
	useWriteBatch bool
}

func NewBadgerContext(prefix []byte, useWriteBatch bool) *BadgerContext {
	return &BadgerContext{
		prefix:        prefix,
		useWriteBatch: useWriteBatch,
	}
}

func NewBadgerNestedContext(prefix []byte, parent *BadgerContext) *BadgerContext {
	prefixedPrefix := append(parent.prefix, prefix...)
	return NewBadgerContext(prefixedPrefix, parent.useWriteBatch)
}

func (bc *BadgerContext) Id() DatabaseId {
	return BADGERDB
}

func (bc *BadgerContext) NestContext(prefixId []byte) Context {
	return NewBadgerNestedContext(prefixId, bc)
}

func castBadgerContextAndGetPrefixedKey(key []byte, ctx Context) (_prefixedKey []byte, _err error) {
	badgerCtx, err := AssertContext[*BadgerContext](ctx, BADGERDB)
	if err != nil {
		return nil, err
	}

	prefixedKey := append(badgerCtx.prefix, key...)
	return prefixedKey, nil
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
