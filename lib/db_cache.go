package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"go.etcd.io/bbolt"
	"io/ioutil"
	"log"
)

// This file came about as a result of encountering an extremely nasty degradation in BadgerDB
// performance caused by rewriting the same key over and over. The reason this degradation occurs
// is because Badger creates a new version on every update and doesn't garbage-collect the old
// versions. Calling Flatten() didn't work, and neither did any of the other things that people
// encountering this issue were told to do (which also didn't work for them). The specific
// instance where we encountered this issue was updating validator mappings at every epoch
// transition for Proof of Stake. As time went on, validator lookups became hopelessly slow
// due to the number of versions that had been created for each validator.
//
// As a result, we decided to put a special in-memory cache in front of Badger that would allow
// us to quickly fetch certain keys that exhibit this edge-case. Ideally, at some point, we would
// fix Badger. For now, this bandaid should work fine, and we could consider using it for other
// keys to increase performance even further.

// Bolt has a layer above key/value pairs which is a bucket. We just throw everything into
// the same bucket for convenience.
var DbCacheBoltdbBucket = []byte("db_cache_bucket")

type DbCache struct {
	PrefixesToCache map[byte]bool
	KeyValueCache   *bbolt.DB
}

var DbCachePrefixes = map[byte]bool{
	Prefixes.PrefixValidatorByStatusAndStakeAmount[0]:           true,
	Prefixes.PrefixSnapshotValidatorSetByStakeAmount[0]:         true,
	Prefixes.PrefixSnapshotStakeToRewardByValidatorAndStaker[0]: true,
	Prefixes.PrefixStakeByValidatorAndStaker[0]:                 true,
	Prefixes.PrefixSnapshotValidatorSetByPKID[0]:                true,
	Prefixes.PrefixValidatorByPKID[0]:                           true,
	Prefixes.PrefixSnapshotValidatorSetByStakeAmount[0]:         true,
	Prefixes.PrefixSnapshotGlobalParamsEntry[0]:                 true,
	Prefixes.PrefixStakeByStakeAmount[0]:                        true,
}

func _enumerateBoltKeysForPrefix(db *bbolt.DB, dbPrefix []byte, keysOnly bool) (
	_keysFound [][]byte, _valsFound [][]byte) {
	// Initialize slices to hold the keys and values found
	keysFound := [][]byte{}
	valsFound := [][]byte{}

	// View transaction
	err := db.View(func(tx *bbolt.Tx) error {
		// Get the bucket using the provided prefix
		b := tx.Bucket(DbCacheBoltdbBucket)
		if b == nil {
			return nil // Return if the bucket doesn't exist
		}

		// Use a cursor to iterate over the keys
		c := b.Cursor()
		prefix := dbPrefix
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			// Copy the key
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			keysFound = append(keysFound, kCopy)

			if !keysOnly {
				// Copy the value if keysOnly is false
				vCopy := make([]byte, len(v))
				copy(vCopy, v)
				valsFound = append(valsFound, vCopy)
			}
		}

		return nil
	})
	if err != nil {
		log.Printf("Failed to enumerate keys for prefix: %v", err)
	}

	return keysFound, valsFound
}

func DumpDbCacheSizes() {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	fmt.Println("DbCache sizes:")
	keys, _ := _enumerateBoltKeysForPrefix(GlobalDeSoParams.DbCache.KeyValueCache, []byte{}, true)
	mapOfSizes := map[byte]int{}
	for _, kk := range keys {
		for pp, _ := range GlobalDeSoParams.DbCache.PrefixesToCache {
			if kk[0] == pp {
				mapOfSizes[pp] += 1
			}
		}
	}
	for kk, vv := range mapOfSizes {
		fmt.Printf("\tKey: %v, Value: %v\n", kk, vv)
	}
}

// FIXME: When we load up the NewDbCache, we need to read in all the existing kvs
// that we care about from Badger or else everything will break.
func NewDbCache(prefixesToCache map[byte]bool) *DbCache {
	// Create a temporary file
	tmpfile, err := ioutil.TempFile("", "boltdb-*.db")
	if err != nil {
		log.Fatal(err)
	}
	//defer os.Remove(tmpfile.Name()) // Clean up the file after we're done

	// Open the BoltDB database on the temporary file
	db, err := bbolt.Open(tmpfile.Name(), 0600, nil)
	if err != nil {
		log.Fatal(err)
	}
	//defer db.Close()

	return &DbCache{
		PrefixesToCache: prefixesToCache,
		KeyValueCache:   db,
	}
}

// TODO: This is a dirty hack that we use to make the DbCache accessible from within
// DbSetWithTxn and DbGetWithTxn. See the comment on DeSoParams for more context.
func InitDbCache() {
	prefixesToCache := DbCachePrefixes
	GlobalDeSoParams.DbCache = NewDbCache(prefixesToCache)
}

func DbCacheGet(key []byte) ([]byte, error) {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	var itemData []byte
	err := GlobalDeSoParams.DbCache.KeyValueCache.View(func(tx *bbolt.Tx) error {
		// Get the bucket using the provided prefix
		b := tx.Bucket(DbCacheBoltdbBucket)
		if b == nil {
			return nil // Return if the bucket doesn't exist
		}

		// Attempt to retrieve the value for the given key
		itemData = b.Get(key)
		if itemData == nil {
			return badger.ErrKeyNotFound
		}

		// Make a copy of the data to ensure it's safe to use outside the transaction
		valCopy := make([]byte, len(itemData))
		copy(valCopy, itemData)
		itemData = valCopy

		return nil
	})
	if err != nil {
		return nil, err
	}
	return itemData, nil
}

func DbCacheSet(key []byte, value []byte) error {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	// Set the item in bolt
	err := GlobalDeSoParams.DbCache.KeyValueCache.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(DbCacheBoltdbBucket)
		if err != nil {
			return err
		}
		return b.Put(key, value)
	})
	if err != nil {
		return err
	}
	return nil
}

func DbCacheDelete(key []byte) error {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	// Delete the item from bolt
	err := GlobalDeSoParams.DbCache.KeyValueCache.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket(DbCacheBoltdbBucket)
		if b == nil {
			return nil // Return if the bucket doesn't exist
		}
		return b.Delete(key)
	})
	if err != nil {
		return err
	}
	return nil
}

func DbCacheEnumerateKeysOnlyForPrefixWithLimitOffsetOrderWithTxn(
	prefix []byte,
	limit int,
	lastSeenKey []byte,
	sortDescending bool,
	canSkipKey func([]byte) bool,
) ([][]byte, error) {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}

	keysFound, _, err := GlobalDeSoParams.DbCache.EnumerateKeysAndValuesForPrefixWithLimitOffsetOrder(
		prefix, limit, lastSeenKey, sortDescending, canSkipKey, true)
	return keysFound, err
}

func DbCacheEnumerateKeysForPrefixWithLimitOffsetOrder(
	prefix []byte,
	limit int,
	lastSeenKey []byte,
	sortDescending bool,
	canSkipKey func([]byte) bool,
) ([][]byte, [][]byte, error) {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	return GlobalDeSoParams.DbCache.EnumerateKeysAndValuesForPrefixWithLimitOffsetOrder(
		prefix, limit, lastSeenKey, sortDescending, canSkipKey, false)
}

func IsDbCachePrefix(prefix byte) bool {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	return GlobalDeSoParams.DbCache.IsPrefix(prefix)
}

func (dbCache *DbCache) IsPrefix(prefix byte) bool {
	return dbCache.PrefixesToCache[prefix]
}

func (dbCache *DbCache) EnumerateKeysAndValuesForPrefixWithLimitOffsetOrder(
	prefix []byte,
	limit int,
	lastSeenKey []byte,
	sortDescending bool,
	canSkipKey func([]byte) bool,
	keysOnly bool,
) ([][]byte, [][]byte, error) {
	if !dbCache.IsPrefix(prefix[0]) {
		return nil, nil, fmt.Errorf("EnumerateKeysOnlyForPrefixWithLimitOffsetOrderWithTxn: " +
			"The DbCache should never be called on a prefix it is not responsible for")
	}

	keysFound := [][]byte{}
	valsFound := [][]byte{}

	// Read in a BoltDB view
	err := dbCache.KeyValueCache.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(DbCacheBoltdbBucket)
		if b == nil {
			return nil
		}

		c := b.Cursor()

		var k, v []byte
		if lastSeenKey != nil {
			// Seek to the last seen key if provided
			k, v = c.Seek(lastSeenKey)
			if k != nil && bytes.Equal(k, lastSeenKey) {
				// Move to the next key after last seen key
				k, v = c.Next()
			}
		} else {
			// Otherwise, seek to the first key that matches the prefix
			k, v = c.Seek(prefix)
		}

		for ; k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if limit > 0 && len(keysFound) >= limit {
				break
			}
			if canSkipKey(k) {
				continue
			}
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			keysFound = append(keysFound, keyCopy)

			if !keysOnly {
				valCopy := make([]byte, len(v))
				copy(valCopy, v)
				valsFound = append(valsFound, valCopy)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return keysFound, valsFound, nil
}
