package lib

import "fmt"

type DatabaseId byte

const (
	BADGERDB DatabaseId = 0
	BOLTDB   DatabaseId = 1
)

type Database interface {
	Setup() error
	GetContext(id []byte) Context
	Update(Context, func(Transaction, Context) error) error
	Close() error
	Cleanup() error
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
	DatabaseId() DatabaseId
}

func AssertDatabaseContext[C any](ctx Context, id DatabaseId) (C, error) {
	var c C
	var ok bool

	if ctx.DatabaseId() != id {
		return c, fmt.Errorf("Invalid Context type got %v expected %v", ctx.DatabaseId(), id)
	}
	c, ok = ctx.(C)
	if !ok {
		return c, fmt.Errorf("Invalid Context assertion, type got %T expected %T", ctx.DatabaseId(), id)
	}
	return c, nil
}
