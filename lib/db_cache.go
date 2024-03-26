package lib

import (
	"bytes"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"sort"
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
	KeyValueCache   map[string][]byte
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
	mapOfSizes := map[byte]int{}
	for kk, _ := range GlobalDeSoParams.DbCache.KeyValueCache {
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
	return &DbCache{
		PrefixesToCache: prefixesToCache,
		KeyValueCache:   make(map[string][]byte),
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
	return GlobalDeSoParams.DbCache.Get(key)
}

func DbCacheSet(key []byte, value []byte) error {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	return GlobalDeSoParams.DbCache.Set(key, value)
}

func DbCacheDelete(key []byte) error {
	if GlobalDeSoParams.DbCache == nil {
		InitDbCache()
	}
	return GlobalDeSoParams.DbCache.Delete(key)
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
	return GlobalDeSoParams.DbCache.EnumerateKeysOnlyForPrefixWithLimitOffsetOrderWithTxn(
		prefix, limit, lastSeenKey, sortDescending, canSkipKey)
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
	return GlobalDeSoParams.DbCache.EnumerateKeysForPrefixWithLimitOffsetOrder(
		prefix, limit, lastSeenKey, sortDescending, canSkipKey)
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

func (dbCache *DbCache) Get(key []byte) ([]byte, error) {
	// If the key is empty, we have nothing to return.
	if len(key) == 0 {
		return nil, badger.ErrKeyNotFound
	}
	if dbCache.PrefixesToCache[key[0]] {
		if value, exists := dbCache.KeyValueCache[string(key)]; exists {
			return value, nil
		}
		// Returning a Badger error here to match the behavior of the real Badger.
		return nil, badger.ErrKeyNotFound
	}
	// This function should never be called on a prefix it is not responsible for.
	panic(fmt.Errorf("Get: The DbCache should never be called on a " +
		"prefix it is not responsible for"))
}

func (dbCache *DbCache) Set(key []byte, value []byte) error {
	if dbCache.PrefixesToCache[key[0]] {
		dbCache.KeyValueCache[string(key)] = value
	}
	return nil
}

func (dbCache *DbCache) Delete(key []byte) error {
	if dbCache.PrefixesToCache[key[0]] {
		delete(dbCache.KeyValueCache, string(key))
	}
	return nil
}

func (dbCache *DbCache) EnumerateKeysOnlyForPrefixWithLimitOffsetOrderWithTxn(
	prefix []byte,
	limit int,
	lastSeenKey []byte,
	sortDescending bool,
	canSkipKey func([]byte) bool,
) ([][]byte, error) {

	if !dbCache.IsPrefix(prefix[0]) {
		return nil, fmt.Errorf("EnumerateKeysOnlyForPrefixWithLimitOffsetOrderWithTxn: " +
			"The DbCache should never be called on a prefix it is not responsible for")
	}

	// Extract the kvs as a slice
	// TODO: This whole thing is inefficient.
	type kv struct {
		k []byte
		v []byte
	}
	kvs := make([]kv, 0, len(dbCache.KeyValueCache))
	for k, v := range dbCache.KeyValueCache {
		// Only consider keys that have the prefix we're looking for.
		if !bytes.HasPrefix([]byte(k), prefix) {
			continue
		}
		kvs = append(kvs, kv{k: []byte(k), v: v})
	}
	// Sort the kvs lexicographically by their key
	if sortDescending {
		sort.Slice(kvs, func(i, j int) bool {
			return bytes.Compare(kvs[i].k, kvs[j].k) > 0 // descending
		})
	} else {
		sort.Slice(kvs, func(i, j int) bool {
			return bytes.Compare(kvs[i].k, kvs[j].k) < 0 // ascending
		})
	}
	// At this point, kvs is sorted lexicographically by the key in the order we want.

	keysFound := [][]byte{}
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
	for _, kv := range kvs {
		// Don't start the iteration until we get to the startingKey
		if !bytes.HasPrefix(kv.k, startingKey) {
			continue
		}
		// The equivalent of ValidForPrefix
		if !bytes.HasPrefix(kv.k, prefix) {
			break
		}
		// Break if at or beyond limit.
		if limit > 0 && len(keysFound) >= limit {
			break
		}
		// Skip if key is before the last seen key. The caller
		// needs to filter out the lastSeenKey in the view as
		// we return any key >= the lastSeenKey.
		if !haveSeenLastSeenKey {
			if !bytes.Equal(kv.k, lastSeenKey) {
				continue
			}
			haveSeenLastSeenKey = true
		}
		// Skip if key can be skipped.
		if canSkipKey(kv.k) {
			continue
		}
		// Copy key.
		keyCopy := make([]byte, len(kv.k))
		copy(keyCopy[:], kv.k[:])
		// Append found entry to return slices.
		keysFound = append(keysFound, keyCopy)
	}
	return keysFound, nil
}

func (dbCache *DbCache) EnumerateKeysForPrefixWithLimitOffsetOrder(
	prefix []byte,
	limit int,
	lastSeenKey []byte,
	sortDescending bool,
	canSkipKey func([]byte) bool,
) ([][]byte, [][]byte, error) {
	if !dbCache.IsPrefix(prefix[0]) {
		return nil, nil, fmt.Errorf("EnumerateKeysOnlyForPrefixWithLimitOffsetOrderWithTxn: " +
			"The DbCache should never be called on a prefix it is not responsible for")
	}

	// Extract the kvs as a slice
	// TODO: This whole thing is inefficient.
	type kv struct {
		k []byte
		v []byte
	}
	kvs := make([]kv, 0, len(dbCache.KeyValueCache))
	for k, v := range dbCache.KeyValueCache {
		// Only consider keys that have the prefix we're looking for.
		if !bytes.HasPrefix([]byte(k), prefix) {
			continue
		}
		kvs = append(kvs, kv{k: []byte(k), v: v})
	}
	// Sort the kvs lexicographically by their key
	if sortDescending {
		sort.Slice(kvs, func(i, j int) bool {
			return bytes.Compare(kvs[i].k, kvs[j].k) > 0 // descending
		})
	} else {
		sort.Slice(kvs, func(i, j int) bool {
			return bytes.Compare(kvs[i].k, kvs[j].k) < 0 // ascending
		})
	}
	// At this point, kvs is sorted lexicographically by the key in the order we want.

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
	for _, kv := range kvs {
		// Don't start the iteration until we get to the startingKey
		if !bytes.HasPrefix(kv.k, startingKey) {
			continue
		}
		// The equivalent of ValidForPrefix
		if !bytes.HasPrefix(kv.k, prefix) {
			break
		}
		// Break if at or beyond limit.
		if limit > 0 && len(keysFound) >= limit {
			break
		}
		// Skip if key is before the last seen key. The caller
		// needs to filter out the lastSeenKey in the view as
		// we return any key >= the lastSeenKey.
		if !haveSeenLastSeenKey {
			if !bytes.Equal(kv.k, lastSeenKey) {
				continue
			}
			haveSeenLastSeenKey = true
		}
		// Skip if key can be skipped.
		if canSkipKey(kv.k) {
			continue
		}
		// Copy key.
		keyCopy := make([]byte, len(kv.k))
		copy(keyCopy[:], kv.k[:])
		// Append found entry to return slices.
		keysFound = append(keysFound, keyCopy)
		valsFound = append(valsFound, kv.v)
	}
	return keysFound, valsFound, nil
}
