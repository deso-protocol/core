package storage

import (
	"fmt"
)

type DatabaseId byte

const (
	BADGERDB DatabaseId = 0
)

// Database is a unified interface for Key-Value databases. Using an additional layer of abstraction atop a native database
// gives us a higher degree of control over how and where the database is used. It allows us to write components with a
// configurable database implementation. Moreover, it allows us to write custom features on top of the database,
// e.g. concurrency control as in DatabaseContext. Many more features can be added in the future, such as introducing
// an event handler that publishes an event whenever we update data in the database.
//
// The Database interface organization is inspired by the BadgerDB API. The Database interface consists of intuitive
// database access methods such as:
// - Update() - used for Read-Write access to the database
// - View()   - used for Read-Only access to the database
// Note that both of these methods are using a callback function, similar to the BadgerDB API. It's also worth noting that
// the callback function is augmented with a Context parameter, used to encapsulate information about the operation's location.
// In case of the BadgerDB, the Context is simply a byte slice prefix prepended to all keys accessed by the Transaction.
// Context can be instantiated using the GetContext() method by passing a byte slice id. The Context interface is meant
// to be simple, and to not hinder the usage of the Database interface. In case of the BadgerDB, it can even be ignored,
// apart from creating a placeholder instance by calling GetContext() with a nil argument.
//
// Lastly, the Database interface has methods responsible for database control, such as:
// - Setup() - used to initialize the database
// - Close() - used to close the database
// - Erase() - used to erase the database
//
// And, for completeness, the Database interface has these miscellaneous methods:
// - GetContext() - used to get a Context instance
// - Id()         - used to get the database id
type Database interface {
	Setup() error
	GetContext(id []byte) Context
	Update(Context, func(Transaction, Context) error) error
	View(Context, func(Transaction, Context) error) error
	Close() error
	Erase() error
	Id() DatabaseId
}

// Transaction is a unified interface for database transactions inside a Database Update or View callback. It's a simple
// interface that allows us to perform basic database operations such as:
// - Set()         - used to set a key-value pair
// - Delete()      - used to delete a key-value pair
// - Get()         - used to get a value for a given key
// - GetIterator() - used to get an Iterator instance
// Note that all of these methods are using a Context parameter, which can be passed down from the Database Update or View.
type Transaction interface {
	Set(key []byte, value []byte, ctx Context) error
	Delete(key []byte, ctx Context) error
	Get(key []byte, ctx Context) ([]byte, error)
	GetIterator(Context) (Iterator, error)
}

// Iterator is a unified interface for database iterators. The current implementation only supports forward iteration.
// The Iterator instance must always be initialized with a Context instance, which can be passed down from the Database
// Update or View. When using the Iterator, the following assumptions must be followed:
//
//	Assumption #1: Newly initialized Iterator always points to nil. Calling Next() moves the iterator to the first key-value pair.
//	Assumption #2: Next() returns false whenever all keys have been exhausted in the current Context.
//	Assumption #3: Close() must be called after the iterator is no longer needed.
//
// This assumption enables the following for-loop usage pattern for the Iterator:
//
//	defer it.Close()
//	for it.Next() {
//		key := it.Key()
//		value, err := it.Value()
//		...
//	}
//
// The Iterator interface consists of basic iterator methods such as:
// - GetContext() - used to get the current Context
// - Value()      - used to get the current value
// - Key()        - used to get the current key
// - Next()       - used to advance the iterator
// - Close()      - used to close the iterator
type Iterator interface {
	GetContext() Context
	Value() ([]byte, error)
	Key() []byte
	Next() bool
	Close()
}

// Context is a unified interface for database contexts. Context is used to encapsulate information about the operation's location.
// In case of the BadgerDB, the Context is simply a byte slice prefix prepended to all keys accessed within a Transaction.
// Context can be instantiated using the GetContext() method on the Database by passing a byte slice id.
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
