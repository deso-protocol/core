package storage

import (
	"bytes"
	"crypto/rand"
	"github.com/golang/glog"
	"github.com/stretchr/testify/require"
	"math"
	"os"
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

// TestBolt_Experiment_10MB_Batch is a BoltDB test in which we write 10MB batch of data to the database.
// In the test, we:
// 		1. Write 100 equal size KV items to the database.
// 		2. Remove 20 items from the database.
// 		3. Retrieve 20 items from the database.
// 		4. Iterate over 20 items in the database.
func TestBolt_Experiment_10MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      10000000,
		BatchSizeItems:      100,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "boltdb-10mb")
	t.Logf("BoltDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	db := NewBoltDatabase(dir)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	ctx := db.GetContext([]byte("TestBucket"))
	GenericTest(db, ctx, testConfig, t)

	// Test nested context
	boltCtx, err := AssertContext[*BoltContext](ctx, BOLTDB)
	require.NoError(err)
	boltNestedCtx := NewBoltNestedContext([]byte("NestedBucket"), boltCtx)
	GenericTest(db, boltNestedCtx, testConfig, t)
}

// TestBolt_Experiment_25MB_Batch is a BoltDB test in which we write 25MB of data to the database.
// In the test, we perform identical operations as in TestBolt_Experiment_10MB_Batch.
func TestBolt_Experiment_25MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      25000000,
		BatchSizeItems:      250,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}

	dir, err := os.MkdirTemp("", "boltdb-25mb")
	t.Logf("BoltDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	db := NewBoltDatabase(dir)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	ctx := db.GetContext([]byte("TestBucket"))
	GenericTest(db, ctx, testConfig, t)
}

// TestBolt_Experiment_100MB_Batch is a BoltDB test in which we write 100MB of data to the database.
// In the test, we perform identical operations as in TestBolt_Experiment_10MB_Batch.
func TestBolt_Experiment_100MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      100000000,
		BatchSizeItems:      1000,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}

	dir, err := os.MkdirTemp("", "boltdb-100mb")
	t.Logf("BoltDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	db := NewBoltDatabase(dir)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	ctx := db.GetContext([]byte("TestBucket"))
	GenericTest(db, ctx, testConfig, t)
}

// TestBadger_Default_Experiment_10MB_Batch is a BadgerDB test in which we write 10MB of data to the database.
// In the test, we:
//  1. Write 100 equal size KV items to the database.
//  2. Remove 20 items from the database.
//  3. Retrieve 20 items from the database.
//  4. Iterate over 20 items in the database.
//  5. Iterate over all items in the database.
func TestBadger_Default_Experiment_10MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      10000000,
		BatchSizeItems:      100,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-default-10mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := DefaultBadgerOptions(dir)
	db := NewBadgerDatabase(opts, false)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Performance_Experiment_10MB_Batch is a BadgerDB test in which we write 10MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch.
func TestBadger_Performance_Experiment_10MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      10000000,
		BatchSizeItems:      100,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-performance-10mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := PerformanceBadgerOptions(dir)
	db := NewBadgerDatabase(opts, false)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Performance_Experiment_25MB_Batch is a BadgerDB test in which we write 25MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Performance" Badger config.
func TestBadger_Performance_Experiment_25MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      25000000,
		BatchSizeItems:      250,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-performance-25mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := PerformanceBadgerOptions(dir)
	db := NewBadgerDatabase(opts, false)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Performance_Experiment_100MB_Batch is a BadgerDB test in which we write 100MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Performance" Badger config.
func TestBadger_Performance_Experiment_100MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      100000000,
		BatchSizeItems:      1000,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-performance-100mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := PerformanceBadgerOptions(dir)
	db := NewBadgerDatabase(opts, false)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Default_WriteBatch_Experiment_10MB_Batch is a BadgerDB test in which we write 10MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Default" Badger config, and Badger's WriteBatch.
func TestBadger_Default_WriteBatch_Experiment_10MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      10000000,
		BatchSizeItems:      100,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-default-writebatch-10mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := DefaultBadgerOptions(dir)
	db := NewBadgerDatabase(opts, true)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Default_WriteBatch_Experiment_25MB_Batch is a BadgerDB test in which we write 25MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Default" Badger config, and Badger's WriteBatch.
func TestBadger_Default_WriteBatch_Experiment_25MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      25000000,
		BatchSizeItems:      250,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-default-writebatch-25mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := DefaultBadgerOptions(dir)
	db := NewBadgerDatabase(opts, true)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Default_WriteBatch_Experiment_100MB_Batch is a BadgerDB test in which we write 100MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Default" Badger config, and Badger's WriteBatch.
func TestBadger_Default_WriteBatch_Experiment_100MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      100000000,
		BatchSizeItems:      1000,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-default-writebatch-100mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := DefaultBadgerOptions(dir)
	db := NewBadgerDatabase(opts, true)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Performance_WriteBatch_Experiment_10MB_Batch is a BadgerDB test in which we write 10MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Performance" Badger config, and Badger's WriteBatch.
func TestBadger_Performance_WriteBatch_Experiment_10MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      10000000,
		BatchSizeItems:      100,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-performance-writebatch-10mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := PerformanceBadgerOptions(dir)
	db := NewBadgerDatabase(opts, true)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Performance_WriteBatch_Experiment_25MB_Batch is a BadgerDB test in which we write 25MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Performance" Badger config, and Badger's WriteBatch.
func TestBadger_Performance_WriteBatch_Experiment_25MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      25000000,
		BatchSizeItems:      250,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-performance-writebatch-25mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := PerformanceBadgerOptions(dir)
	db := NewBadgerDatabase(opts, true)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

// TestBadger_Performance_WriteBatch_Experiment_100MB_Batch is a BadgerDB test in which we write 100MB of data to the database.
// In the test, we perform identical operations as in TestBadger_Default_Experiment_10MB_Batch. This experiment uses the
// "Performance" Badger config, and Badger's WriteBatch.
func TestBadger_Performance_WriteBatch_Experiment_100MB_Batch(t *testing.T) {
	require := require.New(t)

	testConfig := &TestConfig{
		BatchSizeBytes:      100000000,
		BatchSizeItems:      1000,
		BatchItemsRemoved:   20,
		BatchItemsRetrieved: 20,
		BatchItemsIterated:  20,
	}
	dir, err := os.MkdirTemp("", "badgerdb-performance-writebatch-100mb")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := PerformanceBadgerOptions(dir)
	db := NewBadgerDatabase(opts, true)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	badgerCtx := db.GetContext([]byte{})
	GenericTest(db, badgerCtx, testConfig, t)
}

func GenericTest(db Database, ctx Context, config *TestConfig, t *testing.T) {
	require := require.New(t)

	// Generate data and store it in the DB
	kvMap := WriteToDb(db, ctx, config, t)

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
	kv := IterateWithLimit(db, ctx, config, t)
	for _, val := range kv {
		require.Equal(kvMap[val.Key], val.Value)
	}
	require.Equal(true, ValidateKeyValueOrder(kv))

	// Now iterate over all values from the DB and confirm they match the original values.
	kv = IterateWithNoLimit(db, ctx, t)
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

func WriteToDb(db Database, ctx Context, config *TestConfig, t *testing.T) (_kv map[Key][]byte) {
	require := require.New(t)
	kvMap := make(map[Key][]byte)
	valueLenght := int32(config.BatchSizeBytes / config.BatchSizeItems)

	for ii := 0; ii < config.BatchSizeItems; ii++ {
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

func IterateWithLimit(db Database, ctx Context, config *TestConfig, t *testing.T) (_kv []*KeyValue) {
	require := require.New(t)
	iterationCount := 0
	kv := []*KeyValue{}
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

func IterateWithNoLimit(db Database, ctx Context, t *testing.T) (_kv []*KeyValue) {
	testConfig := &TestConfig{
		BatchItemsIterated: math.MaxInt32,
	}
	return IterateWithLimit(db, ctx, testConfig, t)
}
