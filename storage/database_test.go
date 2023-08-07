package storage

import (
	"bytes"
	"crypto/rand"
	"github.com/golang/glog"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

type TestConfig struct {
	// BatchSizeBytes is the size of the batch in bytes.
	BatchSizeBytes int
	// BatchSizeItems is the number of items in the batch.
	BatchSizeItems int
	// BatchItemsRemoved is the number of items removed from the batch as part of the experiment.
	BatchItemsRemoved int
	// BatchItemsRetrieved is the number of items retrieved from the batch as part of the experiment.
	BatchItemsRetrieved int
	// BatchItemsIterated is the number of items iterated over in the batch as part of the experiment.
	BatchItemsIterated int
}

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

type KeyValue struct {
	Key   Key
	Value []byte
}

func NewKeyValue(key []byte, value []byte) *KeyValue {
	return &KeyValue{
		Key:   NewKey(key),
		Value: value,
	}
}

// RandomBytes returns a []byte with random values.
func RandomBytes(numBytes int32) []byte {
	randomBytes := make([]byte, numBytes)
	_, err := rand.Read(randomBytes)
	if err != nil {
		glog.Errorf("Problem reading random bytes: %v", err)
	}
	return randomBytes
}

func GenericTest(db Database, config *TestConfig, t *testing.T) {
	require := require.New(t)

	// Generate data and store it in the DB
	kvMap := WriteToDb(db, config, t)

	// Choose keys to remove and keys to retrieve
	removedKeys := []Key{}
	retrievedKeys := []Key{}
	for key := range kvMap {
		if len(removedKeys) < config.BatchItemsRemoved {
			removedKeys = append(removedKeys, key)
		} else if len(retrievedKeys) < config.BatchItemsRetrieved {
			retrievedKeys = append(retrievedKeys, key)
		} else {
			break
		}
	}

	// Delete keys from DB and confirm they are deleted.
	DeleteFromDB(db, removedKeys, t)
	deletedValues := GetFromDb(db, removedKeys, t)
	for _, val := range deletedValues {
		require.Nil(val)
	}

	// Retrieve keys from DB and confirm they match the original values.
	retrievedValues := GetFromDb(db, retrievedKeys, t)
	for i, val := range retrievedValues {
		require.Equal(kvMap[retrievedKeys[i]], val)
	}

	// Iterate over a couple values from the DB and confirm they match the original values.
	kv := IterateWithLimit(db, config, t)
	for _, val := range kv {
		require.Equal(kvMap[val.Key], val.Value)
	}
	require.Equal(true, ValidateKeyValueOrder(kv))

	// Now iterate over all values from the DB and confirm they match the original values.
	kv = IterateWithNoLimit(db, t)
	for _, val := range kv {
		require.Equal(kvMap[val.Key], val.Value)
	}
	require.Equal(true, ValidateKeyValueOrder(kv))
}

func ValidateKeyValueOrder(kv []*KeyValue) bool {
	for ii := 0; ii < len(kv)-1; ii++ {
		if bytes.Compare(kv[ii].Key.Bytes(), kv[ii+1].Key.Bytes()) > 0 {
			return false
		}
	}
	return true
}

func WriteToDb(db Database, config *TestConfig, t *testing.T) (_kv map[Key][]byte) {
	require := require.New(t)
	kvMap := make(map[Key][]byte)
	valueLenght := int32(config.BatchSizeBytes / config.BatchSizeItems)

	for ii := 0; ii < config.BatchSizeItems; ii++ {
		randomKey := RandomBytes(32)
		keyHash := NewKey(randomKey)
		kvMap[keyHash] = RandomBytes(valueLenght)
	}

	require.NoError(db.Update(func(tx Transaction) error {
		for key, val := range kvMap {
			if err := tx.Set(key.Bytes(), val); err != nil {
				return err
			}
		}
		return nil
	}))
	return kvMap
}

func DeleteFromDB(db Database, keys []Key, t *testing.T) {
	require := require.New(t)
	require.NoError(db.Update(func(tx Transaction) error {
		for _, key := range keys {
			if err := tx.Delete(key.Bytes()); err != nil {
				return err
			}
		}
		return nil
	}))
}

func GetFromDb(db Database, keys []Key, t *testing.T) [][]byte {
	require := require.New(t)
	var values [][]byte
	require.NoError(db.Update(func(tx Transaction) error {
		for _, key := range keys {
			val, err := tx.Get(key.Bytes())
			if err != nil {
				val = nil
			}
			values = append(values, val)
		}
		return nil
	}))
	return values
}

func IterateWithLimit(db Database, config *TestConfig, t *testing.T) (_kv []*KeyValue) {
	require := require.New(t)
	iterationCount := 0
	kv := []*KeyValue{}
	require.NoError(db.Update(func(tx Transaction) error {
		it, err := tx.GetIterator([]byte{})
		require.NoError(err)
		defer it.Close()
		for it.Next() {
			k := it.Key()
			v, err := it.Value()
			require.NoError(err)
			require.NotNil(k)
			require.NotNil(v)
			kv = append(kv, NewKeyValue(k, v))
			iterationCount++
			if iterationCount >= config.BatchItemsIterated {
				break
			}
		}
		return nil
	}))
	return kv
}

func IterateWithNoLimit(db Database, t *testing.T) (_kv []*KeyValue) {
	testConfig := &TestConfig{
		BatchItemsIterated: math.MaxInt32,
	}
	return IterateWithLimit(db, testConfig, t)
}
