package lib

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/decred/dcrd/lru"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
	"math/big"
	"reflect"
	"sort"
	"sync/atomic"
)

// MODP16 is a large MODP prime number taken from RFC 3526. We use the prime with index 16.
// The reason why we chose this particular number is mainly because we have certainty that it is a prime.
// This prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
// https://datatracker.ietf.org/doc/rfc3526/?include_text=1
// We can compute it with the following four lines of python code:
/*
	from mpmath import mp
	mp.dps = 4000
	modp16 = 2**4096 - 2**4032 - 1 + (2 ** 64) * (mp.floor((2**3966) * mp.pi) + 240904)
	print(hex(int(mp.nstr(modp16, 100000)[:-2])))
*/
var MODP16 = []byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B,
	0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
	0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
	0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
	0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38, 0x6B, 0xFB,
	0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
	0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8,
	0xFD, 0x24, 0xCF, 0x5F, 0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
	0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
	0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B, 0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
	0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6,
	0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
	0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB,
	0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D,
	0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7, 0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
	0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
	0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C, 0xBB, 0xE1, 0x17, 0x57,
	0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
	0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12,
	0xA7, 0x87, 0xE6, 0xD7, 0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18, 0x6A, 0xF4, 0xE2, 0x3C,
	0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA, 0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
	0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6, 0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D,
	0x99, 0xB2, 0x96, 0x4F, 0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED, 0x1F, 0x61, 0x29, 0x70,
	0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76, 0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
	0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC, 0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9,
	0x34, 0x06, 0x31, 0x99, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

const ModulusLength = 512

// StateChecksum is used to verify integrity of state data. When syncing state from
// peers, we need to ensure that we are receiving the same copy of the database.
// Traditionally, this has been done using Merkle Trees; however, Merkle trees incur
// O(log n) computational complexity for updates and O(n) space complexity, where n
// is the number of leaves in the tree.
//
// Instead, we use a structure that allows us to have an O(1) time and space complexity,
// and maintains a higher safety. The structure is inspired by the generalized K-Sum problem,
// where given a set of number L, we want to find a subset of elements in L that XORs to 0.
// However, this problem can be solved efficiently with dynamic programming based on the
// fact that if a ^ b = 0, then any prefix of a and b also XORs to 0, that is a[:i] ^ b[:i] = 0.
// The dynamic algorithm solves the K-Sum problem on the prefix, and keeps growing the prefix.
// K-Sum can be generalized to any algebraic group. That is, given a group G, zero element 0,
// operation +, and set of group elements L, find a subset of L such the +(a_i) = 0.
// https://link.springer.com/content/pdf/10.1007%2F3-540-45708-9_19.pdf
// TODO: I think we need to use the multiplicative group, unfortunately. Seems like the DLP
// assumption only holds if the factorization is difficult.
type StateChecksum struct {
	Checksum big.Int
	Modulus  big.Int
}

// Initialize starts the state checksum by initializing it to zero.
// We also set the prime modulus as the MODP
func (sc *StateChecksum) Initialize() {
	sc.Checksum = *big.NewInt(0)

	sc.Modulus = big.Int{}
	sc.Modulus.SetBytes(MODP16)
}

func (sc *StateChecksum) AddBytes(bytes []byte) {
	out := make([]byte, ModulusLength)
	hash := sha3.NewShake256()
	hash.Write(bytes)
	hash.Read(out)

	z := big.Int{}
	z.SetBytes(out)
	z.Add(&z, &sc.Checksum)
	z.Mod(&z, &sc.Modulus)

	sc.Checksum = z
}

func (sc *StateChecksum) RemoveBytes(bytes []byte) {
	out := make([]byte, ModulusLength)
	hash := sha3.NewShake256()
	hash.Write(bytes)
	hash.Read(out)

	z := big.Int{}
	z.SetBytes(out)
	z.Mod(&z, &sc.Modulus)
	z.Sub(&sc.Modulus, &z)
	z.Add(&sc.Checksum, &z)
	z.Mod(&z, &sc.Modulus)

	sc.Checksum = z
}

type Snapshot struct {
	// Cache is used to store most recent DB records that we've read/wrote.
	// This is particularly useful for maintaining ancestral records, because
	// it saves us read time when we're writing to DB during utxo_view flush.
	Cache            lru.KVCache

	// BlockHeight is the height of the snapshot.
	BlockHeight      uint64

	// Checksum allows us to confirm integrity of the state so that when we're
	// syncing with peers, we are confident that data wasn't tampered with.
	Checksum         *StateChecksum

	// AncestralMap keeps track of original data in place of modified records
	// during utxo_view flush, which is where we're modifying state data.
	AncestralMap     map[string][]byte

	// NotExistsMap keeps track of non-existent records in the DB. We need to
	// do this because we need to distinguish non-existent records from []byte{}.
	NotExistsMap     map[string]bool

	// MapKeyList is a list of keys in AncestralMap and NotExistsMap. We will sort
	// it so that writes to BadgerDB are faster
	MapKeyList       []string

	// DBWriteSemaphore is an atomically accessed semaphore counter that will be
	// used to mitigate DB race conditions between sync and utxo_view flush.
	DBWriteSemaphore int32

	// brokenSnapshot indicates that we need to rebuild entire snapshot from scratch.
	// Updates to the snapshot happen in the background, so sometimes they can be broken
	// by unexpected concurrency. One such edge-case is long block reorg occurring after
	// moving to next snapshot version. Health checks will detect these and set brokenSnapshot.
	brokenSnapshot   bool
}

// NewSnapshot creates a new snapshot with specified cache size.
// TODO: make sure we don't snapshot when using PG
func NewSnapshot(cacheSize uint32) (*Snapshot, error) {
	if cacheSize == 0 {
		return nil, fmt.Errorf("NewSnapshot: Error initializing snapshot, cache size should not be 0")
	}

	// Initialize the checksum.
	checksum := &StateChecksum{}
	checksum.Initialize()

	// Set the snapshot
	snap := &Snapshot{
		Cache:            lru.NewKVCache(uint(cacheSize)),
		BlockHeight:      uint64(0),
		Checksum:         checksum,
		AncestralMap:     make(map[string][]byte),
		NotExistsMap:     make(map[string]bool),
		DBWriteSemaphore: int32(0),
		brokenSnapshot:   false,
	}

	return snap, nil
}

func (snap *Snapshot) String() string {
	return fmt.Sprintf("< Snapshot | height: %v | broken: %v >", snap.BlockHeight, snap.brokenSnapshot)
}

func (snap *Snapshot) IncrementSemaphore() {
	currentSemaphore := atomic.LoadInt32(&snap.DBWriteSemaphore)
	if currentSemaphore > 0 {
		snap.brokenSnapshot = true
		glog.Errorf("UtxoView.FlushToDbWithTxn: Race condition in flush to snapshot, " +
			"current DBWriteSemaphore: %v", currentSemaphore)
	}
	atomic.AddInt32(&snap.DBWriteSemaphore, 1)
}

// PrepareAncestralRecord sets an adequate record in AncestralMap or NotExistsMap.
func (snap *Snapshot) PrepareAncestralRecord(key string, value []byte, existed bool) {
	// If the record was not found, we add it to the NotExistsMap, otherwise to AncestralMap.
	// We record the key in MapKeyList.
	snap.MapKeyList = append(snap.MapKeyList, key)
	if existed {
		snap.AncestralMap[key] = value
		// We also have to remove the previous value from the state checksum.
		// Because checksum is commutative, we can safely remove the past value here.
		snap.Checksum.RemoveBytes(value)
	} else {
		snap.NotExistsMap[key] = true
	}
}

// _getCurrentPrefixAndKey is used to get an ancestral record key from a main DB key.
// 		<prefix, type [1]byte, blockHeight [10]byte, key> -> <>
func (snap *Snapshot) _getCurrentPrefixAndKey (notExistsRecord bool, key []byte) []byte {
	var prefix []byte

	// Append the ancestral record prefix.
	prefix = append(prefix, _PrefixAncestralRecords...)

	// Append the type
	// 		0 - non-existing main DB key
	//		1 - existing main DB key
	typeByte := []byte{1}
	if notExistsRecord {
		typeByte = []byte{0}
	}
	prefix = append(prefix, typeByte...)

	// Append block height, which is the current snapshot identifier.
	prefix = append(prefix, UintToBuf(snap.BlockHeight)...)

	// Finally, append the main DB key.
	return append(prefix, key...)
}

// FlushAncestralRecords updates the ancestral records after a utxo_view flush.
// This function should be called in a go-routine after all utxo_view flushes.
func (snap *Snapshot) FlushAncestralRecords(handle *badger.DB) {
	// If snapshot is broken then there's nothing to do.
	if snap.brokenSnapshot {
		atomic.AddInt32(&snap.DBWriteSemaphore, int32(-1))
		glog.Errorf("Snapshot.FlushAncestralRecords: Broken snapshot, aborting")
		return
	}

	// First sort the MapKeyList so that we write to BadgerDB in order.
	sort.Strings(snap.MapKeyList)

	// We launch a new read-write transaction to set the records.
	err := handle.Update(func(txn *badger.Txn) error {
		// Iterate through all now-sorted keys.
		for _, key := range snap.MapKeyList {
			// We store keys as strings because they're easier to store and sort this way.
			keyBytes, err := hex.DecodeString(key)
			if err != nil {
				return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
					"decoding MapKeyList key: %v", key)
			}

			// We check whether this record is already present in ancestral records,
			// if so then there's nothing to do. What we want is err == badger.ErrKeyNotFound
			_, err = txn.Get(keyBytes)
			if err != nil && err != badger.ErrKeyNotFound {
				return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
					"reading exsiting record in the DB at key: %v", key)
			}
			if err == nil {
				continue
			}

			// If we get here, it means that no record existed in ancestral records at key.
			// The key was either added to AncestralMap or NotExistsMap during flush.
			if value, exists := snap.AncestralMap[key]; exists {
				err = txn.Set(snap._getCurrentPrefixAndKey(false, keyBytes), value)
				if err != nil {
					return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
						"flushing a record from AncestralMap at key %v:", key)
				}
			} else if _, exists = snap.NotExistsMap[key]; exists {
				err = txn.Set(snap._getCurrentPrefixAndKey(true, keyBytes), []byte{})
				if err != nil {
					return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
						"flushing a record from NotExistsMap at key %v:", key)
				}
			} else {
				return fmt.Errorf("Snapshot.FlushAncestralRecords: Error, key is not " +
					"in AncestralMap nor NotExistsMap. This should never happen")
			}
		}
		return nil
	})
	if err != nil {
		// If any error occurred, then the snapshot is potentially broken.
		snap.brokenSnapshot = true
		glog.Errorf("Snapshot.FlushAncestralRecords: Problem flushing snapshot %v, Error %v", snap, err)
	}

	// Reset ancestral record structures
	snap.MapKeyList = []string{}
	snap.AncestralMap = make(map[string][]byte)
	snap.NotExistsMap = make(map[string]bool)
	// Decrement snapshot semaphore counter.
	atomic.AddInt32(&snap.DBWriteSemaphore, int32(-1))
}

func (snap *Snapshot) isState(key []byte) bool {
	return isStateKey(key) && !snap.brokenSnapshot
}

type DBEntry struct {
	Key   string
	Entry string
}

func (snap *Snapshot) GetMostRecentSnapshot(handle *badger.DB) []*DBEntry {
	DBEntries := []*DBEntry{}
	for ii := 0; ii < len(statePrefixes); ii++ {
		prefix := statePrefixes[ii]
		lastPrefix := prefix
		for {
			k1, v1, full, _ := DBIteratePrefixKeys(handle, lastPrefix, uint32(8<<8))
			for i := 0; i < len(*k1); i++ {
				fmt.Printf("Keys:%v\n Values:%v\n", (*k1)[i], (*v1)[i])
			}
			for jj, key := range *k1 {
				if len(DBEntries) > 0 &&
					!reflect.DeepEqual(DBEntries[len(DBEntries)-1].Key, key) {

					DBEntries = append(DBEntries, &DBEntry{
						Key:   key,
						Entry: (*v1)[jj],
					})
				}
			}
			lastPrefix, _ = hex.DecodeString((*k1)[len(*k1)-1])
			if !full || !bytes.HasPrefix(lastPrefix, _PrefixUtxoKeyToUtxoEntry) {
				break
			}
		}
	}

	return DBEntries
}
