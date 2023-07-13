package lib

import (
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

const (
	MB25                     = 25000000
	NumKeys25MBBatch         = 250
	NumRemoveKeys25MBBatch   = 20
	NumRetrieveKeys25MBBatch = 20
)

type Key [32]byte

func NewKey(key []byte) Key {
	var k Key
	copy(k[:], key[:])
	return k
}

func (k Key) Bytes() []byte {
	copyKey := make([]byte, len(k[:]))
	copy(copyKey, k[:])
	return copyKey
}

func TestBolt25MB(t *testing.T) {
	require := require.New(t)
	dir, err := os.MkdirTemp("", "boltdb")
	require.NoError(err)

	db := NewBoltDatabase(dir)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	ctx := db.GetContext([]byte("TestBucket"))
	Generic25MBBatchTest(db, ctx, t)

	// Test nested context
	boltCtx, err := AssertContext[*BoltContext](ctx, BOLTDB)
	require.NoError(err)
	boltNestedCtx := NewBoltNestedContext([]byte("NestedBucket"), boltCtx)
	Generic25MBBatchTest(db, boltNestedCtx, t)
}

func TestBadger25MB(t *testing.T) {
	require := require.New(t)
	dir, err := os.MkdirTemp("", "badgerdb")
	require.NoError(err)

	db := NewBadgerDatabase(dir)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	Generic25MBBatchTest(db, badgerCtx, t)
}

func Generic25MBBatchTest(db Database, ctx Context, t *testing.T) {
	require := require.New(t)

	// Generate 25 MB of data and store it in the DB
	kvMap := Write25MBBatchToDb(db, ctx, t)

	// Choose keys to remove and keys to retrieve
	removedKeys := []Key{}
	retrievedKeys := []Key{}
	for key := range kvMap {
		if len(removedKeys) < NumRemoveKeys25MBBatch {
			removedKeys = append(removedKeys, key)
		} else if len(retrievedKeys) < NumRetrieveKeys25MBBatch {
			retrievedKeys = append(retrievedKeys, key)
		} else {
			break
		}
	}

	// Delete keys from DB and confirm they are deleted.
	DeleteFromDB(db, removedKeys, ctx, t)
	deletedValues := GetFromDb(db, removedKeys, ctx, t)
	for _, val := range deletedValues {
		require.Nil(val)
	}

	// Retrieve keys from DB and confirm they match the original values.
	retrievedValues := GetFromDb(db, retrievedKeys, ctx, t)
	for i, val := range retrievedValues {
		require.Equal(kvMap[retrievedKeys[i]], val)
	}

	// Iterate over a couple values from the DB and confirm they match the original values.
	IterateOverDb(db, ctx, t)
}

func Write25MBBatchToDb(db Database, ctx Context, t *testing.T) (_kv map[Key][]byte) {
	require := require.New(t)
	kvMap := make(map[Key][]byte)
	valueLenght := int32(MB25 / NumKeys25MBBatch)

	for i := 0; i < NumKeys25MBBatch; i++ {
		randomKey := RandomBytes(32)
		keyHash := NewKey(randomKey)
		kvMap[keyHash] = RandomBytes(valueLenght)
	}

	require.NoError(db.Update(ctx, func(tx Transaction, ctx Context) error {
		for key, val := range kvMap {
			if err := tx.Set(key.Bytes(), val, ctx); err != nil {
				return err
			}
		}
		return nil
	}))
	return kvMap
}

func DeleteFromDB(db Database, keys []Key, ctx Context, t *testing.T) {
	require := require.New(t)
	require.NoError(db.Update(ctx, func(tx Transaction, ctx Context) error {
		for _, key := range keys {
			if err := tx.Delete(key.Bytes(), ctx); err != nil {
				return err
			}
		}
		return nil
	}))
}

func GetFromDb(db Database, keys []Key, ctx Context, t *testing.T) [][]byte {
	require := require.New(t)
	var values [][]byte
	require.NoError(db.Update(ctx, func(tx Transaction, ctx Context) error {
		for _, key := range keys {
			val, err := tx.Get(key.Bytes(), ctx)
			if err != nil {
				val = nil
			}
			values = append(values, val)
		}
		return nil
	}))
	return values
}

func IterateOverDb(db Database, ctx Context, t *testing.T) {
	require := require.New(t)
	require.NoError(db.Update(ctx, func(tx Transaction, ctx Context) error {
		it, err := tx.GetIterator(ctx)
		require.NoError(err)
		defer it.Close()
		for it.Next() {
			k := it.Key()
			v, err := it.Value()
			require.NoError(err)
			require.NotNil(k)
			require.NotNil(v)
		}
		return nil
	}))
}
