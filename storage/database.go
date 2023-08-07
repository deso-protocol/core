package storage

type DatabaseId byte

const (
	BADGERDB DatabaseId = 0
)

// Database is a unified interface for Key-Value databases. Using an additional layer of abstraction atop a native database
// gives us a higher degree of control over how and where the database is used. It allows us to write components with a
// configurable database implementation. Many features can be added this way, such as adding an event handler for database
// that publishes an event whenever we update the database. We can also create a logging wrapper around database.
//
// The Database interface organization is inspired by the BadgerDB API. We have the intuitive API to access the database:
// - Update() - used for Read-Write access to the database
// - View()   - used for Read-Only access to the database
// Note that both of these methods are using a callback function, similar to the BadgerDB API.
// Lastly, the Database interface has methods responsible for database control, such as:
// - Setup() - used to initialize the database
// - Close() - used to close the database
// - Erase() - used to erase the database
type Database interface {
	Setup() error
	Update(func(Transaction) error) error
	View(func(Transaction) error) error
	Close() error
	Erase() error
}

// Transaction is a unified interface for database transactions inside a Database Update or View callback. It's a simple
// interface that allows us to perform basic database operations such as:
// - Set()         - used to set a key-value pair
// - Delete()      - used to delete a key-value pair
// - Get()         - used to get a value for a given key
// - GetIterator() - used to get an Iterator instance on a provided key prefix
type Transaction interface {
	Set(key []byte, value []byte) error
	Delete(key []byte) error
	Get(key []byte) ([]byte, error)
	GetIterator(prefix []byte) (Iterator, error)
}

// Iterator is a unified interface for database iterators. The current implementation only supports forward iteration.
// When using the Iterator, the following assumptions must be followed:
//
//	Assumption #1: Newly initialized Iterator always points to nil. Calling Next() moves the iterator to the first key-value pair.
//	Assumption #2: Next() returns false whenever all keys have been exhausted in the current prefix.
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
// - Value()      - used to get the current value
// - Key()        - used to get the current key
// - Next()       - used to advance the iterator
// - Close()      - used to close the iterator
type Iterator interface {
	Value() ([]byte, error)
	Key() []byte
	Next() bool
	Close()
}
