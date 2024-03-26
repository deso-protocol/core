package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v4"
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

type DbCache struct {
	PrefixesToCache map[byte]bool
	KeyValueCache   *badger.DB
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

func DumpDbCacheSizes() {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	fmt.Println("DbCache sizes:")
	keys, _ := _enumerateKeysForPrefix(GlobalDeSoParams.DbCache.KeyValueCache, []byte{}, true)
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
	opts := badger.DefaultOptions("").WithInMemory(true)
	// Open the DB with options
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
	}
	// FIXME: Need to handle closing probably. But maybe not because it's just in-memory
	// anyway.
	// defer db.Close()

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
	err := GlobalDeSoParams.DbCache.KeyValueCache.View(func(txn *badger.Txn) error {
		// If record doesn't exist in cache, we get it from the DB.
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		itemData, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
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
	// Set the item in badger
	err := GlobalDeSoParams.DbCache.KeyValueCache.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
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
	// Delete the item from badger
	err := GlobalDeSoParams.DbCache.KeyValueCache.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
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

	// If provided, start at the last seen key.
	startingKey := prefix
	haveSeenLastSeenKey := true
	if lastSeenKey != nil {
		startingKey = lastSeenKey
		haveSeenLastSeenKey = false
		if limit > 0 {
			// Need to increment limit by one (if non-zero) since
			// we include the lastSeenKey/lastSeenValue.
			limit += 1
		}
	}

	opts := badger.DefaultIteratorOptions
	// Search keys in reverse order if sort DESC.
	if sortDescending {
		opts.Reverse = true
		startingKey = append(startingKey, 0xff)
	}
	if keysOnly {
		opts.PrefetchValues = false
	}
	opts.Prefix = prefix
	// Read in a badger view
	err := dbCache.KeyValueCache.View(func(txn *badger.Txn) error {
		nodeIterator := txn.NewIterator(opts)
		defer nodeIterator.Close()

		for nodeIterator.Seek(startingKey); nodeIterator.ValidForPrefix(prefix); nodeIterator.Next() {
			// Break if at or beyond limit.
			if limit > 0 && len(keysFound) >= limit {
				break
			}
			key := nodeIterator.Item().Key()
			// Skip if key is before the last seen key. The caller
			// needs to filter out the lastSeenKey in the view as
			// we return any key >= the lastSeenKey.
			if !haveSeenLastSeenKey {
				if !bytes.Equal(key, lastSeenKey) {
					continue
				}
				haveSeenLastSeenKey = true
			}
			// Skip if key can be skipped.
			if canSkipKey(key) {
				continue
			}
			// Copy key.
			keyCopy := make([]byte, len(key))
			copy(keyCopy[:], key[:])
			// Append found entry to return slices.
			keysFound = append(keysFound, keyCopy)

			// Copy value.
			if !keysOnly {
				valCopy, err := nodeIterator.Item().ValueCopy(nil)
				if err != nil {
					return err
				}
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
