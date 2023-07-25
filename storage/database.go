package storage

import (
	"fmt"
	"sync"
)

type DatabaseId byte

const (
	BADGERDB DatabaseId = 0
	BOLTDB   DatabaseId = 1
)

type Database interface {
	Setup() error
	GetContext(id []byte) Context
	Update(Context, func(Transaction, Context) error) error
	View(Context, func(Transaction, Context) error) error
	Close() error
	Erase() error
	Id() DatabaseId
}

type Transaction interface {
	Set(key []byte, value []byte, ctx Context) error
	Delete(key []byte, ctx Context) error
	Get(key []byte, ctx Context) ([]byte, error)
	GetIterator(Context) (Iterator, error)
}

type Iterator interface {
	GetContext() Context
	Value() ([]byte, error)
	Key() []byte
	Next() bool
	Close()
}

type Context interface {
	Id() DatabaseId
	NestContext(contextId []byte) Context
}

func AssertContext[C any](ctx Context, id DatabaseId) (C, error) {
	var c C
	var ok bool

	if ctx.Id() != id {
		return c, fmt.Errorf("Invalid Context type got %v expected %v", ctx.Id(), id)
	}
	c, ok = ctx.(C)
	if !ok {
		return c, fmt.Errorf("Invalid Context assertion, type got %T expected %T", ctx.Id(), id)
	}
	return c, nil
}

type DatabaseContext struct {
	sync.RWMutex

	Db  Database
	Ctx Context
}

func NewDatabaseContext(db Database, ctx Context) *DatabaseContext {
	return &DatabaseContext{Db: db, Ctx: ctx}
}

func (cdb *DatabaseContext) Setup() error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Setup()
}

func (cdb *DatabaseContext) GetContext(id []byte) Context {
	return cdb.Db.GetContext(id)
}

func (cdb *DatabaseContext) Update(ctx Context, f func(Transaction, Context) error) error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Update(ctx, f)
}

func (cdb *DatabaseContext) View(ctx Context, f func(Transaction, Context) error) error {
	cdb.RLock()
	defer cdb.RUnlock()

	return cdb.Db.View(ctx, f)
}

func (cdb *DatabaseContext) Close() error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Close()
}

func (cdb *DatabaseContext) Erase() error {
	cdb.Lock()
	defer cdb.Unlock()

	return cdb.Db.Erase()
}

func (cdb *DatabaseContext) Id() DatabaseId {
	return cdb.Db.Id()
}

func (cdb *DatabaseContext) NestContext(localId []byte) Context {
	return cdb.Ctx.NestContext(localId)
}
