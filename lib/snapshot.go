package lib

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/circl/group"
	"github.com/decred/dcrd/lru"
	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/oleiade/lane"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
	"io"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
)

// -------------------------------------------------------------------------------------
// StateChecksum
// -------------------------------------------------------------------------------------

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
	curve group.Group
	checksum group.Element

	Semaphore *semaphore.Weighted
	Ctx context.Context
	AddMutex sync.Mutex

	maxWorkers int64
	dst []byte
}

// Initialize starts the state checksum by initializing it to zero.
func (sc *StateChecksum) Initialize() {
	sc.curve = group.Ristretto255
	sc.checksum = sc.curve.Identity()
	sc.maxWorkers = int64(runtime.GOMAXPROCS(0))
	sc.Semaphore = semaphore.NewWeighted(sc.maxWorkers)
	sc.Ctx = context.TODO()
	sc.dst = []byte("DESO-DST-V1:Ristretto255")
}

func (sc *StateChecksum) AddBytes(bytes []byte) error {
	if err := sc.Semaphore.Acquire(sc.Ctx, 1); err != nil {
		return errors.Wrapf(err, "StateChecksum.AddBytes: problem acquiring semaphore")
	}

	go func(sc *StateChecksum, bytes []byte) {
		defer sc.Semaphore.Release(1)

		hashElement := sc.curve.HashToElement(bytes, sc.dst)

		sc.AddMutex.Lock()
		sc.checksum.Add(sc.checksum, hashElement)
		sc.AddMutex.Unlock()
	}(sc, bytes)

	return nil
}

func (sc *StateChecksum) RemoveBytes(bytes []byte) error {
	if err := sc.Semaphore.Acquire(sc.Ctx, 1); err != nil {
		return errors.Wrapf(err, " StateChecksum.RemoveBytes: problem acquiring semaphore")
	}

	go func(sc *StateChecksum, bytes []byte) {
		defer sc.Semaphore.Release(1)

		hashElement := sc.curve.HashToElement(bytes, sc.dst)
		hashElement = hashElement.Neg(hashElement)

		sc.AddMutex.Lock()
		sc.checksum.Add(sc.checksum, hashElement)
		sc.AddMutex.Unlock()
	}(sc, bytes)
	return nil
}

func (sc *StateChecksum) GetChecksum() (group.Element, error) {
	if err := sc.Semaphore.Acquire(sc.Ctx, sc.maxWorkers); err != nil {
		return nil, errors.Wrapf(err, "StateChecksum.GetChecksum: problem acquiring semaphore")
	}
	defer sc.Semaphore.Release(sc.maxWorkers)

	// Clone the checksum by adding it to identity. That's faster than doing ToBytes / FromBytes
	checksumCopy := group.Ristretto255.Identity()
	checksumCopy.Add(checksumCopy, sc.checksum)

	return checksumCopy, nil
}

func (sc *StateChecksum) Wait() error {
	if err := sc.Semaphore.Acquire(sc.Ctx, sc.maxWorkers); err != nil {
		return errors.Wrapf(err, "StateChecksum.Wait: problem acquiring semaphore")
	}
	defer sc.Semaphore.Release(sc.maxWorkers)
	return nil
}

// Don't use this function to deep copy the checksum, use the copy pattern in GetChecksum instead.
// Parsing checksum to bytes is doing an inverse square root so it is slow.
func (sc *StateChecksum) ToBytes() ([]byte, error) {
	checksum, err := sc.GetChecksum()
	if err != nil {
		return nil, errors.Wrapf(err, "StateChecksum.ToBytes: problem getting checksum")
	}

	checksumBytes, err := checksum.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "stateChecksum.ToBytes: error during MarshalBinary")
	}
	return checksumBytes, nil
}

// -------------------------------------------------------------------------------------
// DBEntry
// -------------------------------------------------------------------------------------

type DBEntry struct {
	Key   []byte
	Value []byte
}

func (entry *DBEntry) Encode() []byte {
	data := []byte{}

	data = append(data, UintToBuf(uint64(len(entry.Key)))...)
	data = append(data, entry.Key...)
	data = append(data, UintToBuf(uint64(len(entry.Value)))...)
	data = append(data, entry.Value...)
	return data
}

func (entry *DBEntry) Decode(rr io.Reader) error {
	var keyLen, entryLen uint64
	var err error

	keyLen, err = ReadUvarint(rr)
	if err != nil {
		return err
	}

	entry.Key = make([]byte, keyLen)
	_, err = io.ReadFull(rr, entry.Key)
	if err != nil {
		return err
	}

	entryLen, err = ReadUvarint(rr)
	if err != nil {
		return err
	}

	entry.Value = make([]byte, entryLen)
	_, err = io.ReadFull(rr, entry.Value)
	if err!= nil {
		return err
	}

	return nil
}

// DBEntryKeyOnlyFromBytes is used as a dummy entry that only contains the key.
func DBEntryKeyOnlyFromBytes(key []byte) *DBEntry {
	dbEntry := &DBEntry{}
	dbEntry.Key = make([]byte, len(key))
	copy(dbEntry.Key, key)

	return dbEntry
}

func DBEntryFromBytes(key []byte, value []byte) *DBEntry {
	entry := DBEntryKeyOnlyFromBytes(key)
	entry.Value = make([]byte, len(value))
	copy(entry.Value, value)

	return entry
}

// EmptyDBEntry indicates an empty DB entry.
func EmptyDBEntry() *DBEntry {
	// We do not use prefix 0 for state so we can use it as an empty entry for convenience.
	return &DBEntry{
		Key: []byte{0},
		Value: []byte{},
	}
}

// IsEmpty return true if the DBEntry is empty, false otherwise.
func (entry *DBEntry) IsEmpty() bool {
	return reflect.DeepEqual(entry.Key, []byte{0})
}

// -------------------------------------------------------------------------------------
// Snapshot
// -------------------------------------------------------------------------------------

var (
	_PrefixNonExistentAncestralRecord = []byte{0}

	_PrefixExistentAncestralRecord = []byte{1}

	_PrefixSnapshotHealth = []byte{2}
)

type AncestralCache struct {
	index uint64

	// AncestralMap keeps track of original data in place of modified records
	// during utxo_view flush, which is where we're modifying state data.
	AncestralMap    map[string][]byte //*lane.Deque//map[uint64]map[string][]byte

	// NotExistsMap keeps track of non-existent records in the DB. We need to
	// do this because we need to distinguish non-existent records from []byte{}.
	NotExistsMap     map[string]bool//*lane.Deque//map[uint64]map[string]bool

	// MapKeyList is a list of keys in AncestralMap and NotExistsMap. We will sort
	// it so that writes to BadgerDB are faster
	MapKeyList       []string//*lane.Deque//map[uint64][]string
}

func NewAncestralCache(index uint64) *AncestralCache {
	return &AncestralCache{
		index: index,
		AncestralMap: make(map[string][]byte),
		NotExistsMap: make(map[string]bool),
		MapKeyList: make([]string, 0),
	}
}

type Snapshot struct {
	// DB is used to store ancestral records
	Db *badger.DB

	// Cache is used to store most recent DB records that we've read/wrote.
	// This is particularly useful for maintaining ancestral records, because
	// it saves us read time when we're writing to DB during utxo_view flush.
	Cache            lru.KVCache

	// BlockHeight is the height of the snapshot.
	BlockHeight      uint64

	BlockHeightModulus uint64
	DeleteChannel chan uint64
	LastCounter        uint64
	// Do we even need to use a mutex if we're going to hold it?
	DBLock sync.RWMutex

	// FlushCounter is used to offset ancestral records flush to occur only after x blocks.
	FlushCounter     uint64
	FlushCounterModulus uint64
	CounterChannel chan uint64
	ExitChannel chan bool

	// BatchSize is the size in bytes of the
	BatchSize uint32

	// Checksum allows us to confirm integrity of the state so that when we're
	// syncing with peers, we are confident that data wasn't tampered with.
	Checksum         *StateChecksum

	AncestralMemory *lane.Deque

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
func NewSnapshot(cacheSize uint32, dataDirectory string) (*Snapshot, error) {
	if cacheSize == 0 {
		return nil, fmt.Errorf("NewSnapshot: Error initializing snapshot, cache size should not be 0")
	}

	// Initialize database
	snapshotDir := filepath.Join(GetBadgerDbPath(dataDirectory), "snapshot")
	snapshotOpts := badger.DefaultOptions(snapshotDir)
	// TODO: Remove this
	snapshotOpts.ValueDir = GetBadgerDbPath(snapshotDir)
	snapshotOpts.MemTableSize = 1024 << 20
	glog.Infof("Snapshot BadgerDB Dir: %v", snapshotOpts.Dir)
	glog.Infof("Snapshot BadgerDB ValueDir: %v", snapshotOpts.ValueDir)
	snapshotDb, err := badger.Open(snapshotOpts)
	if err != nil {
		glog.Fatal(err)
	}

	// Initialize the checksum.
	checksum := &StateChecksum{}
	checksum.Initialize()

	// Set the snapshot
	snap := &Snapshot{
		Db:                  snapshotDb,
		Cache:               lru.NewKVCache(uint(cacheSize)),
		BlockHeight:         uint64(0),
		BlockHeightModulus:  uint64(900),
		FlushCounter:        uint64(0),
		FlushCounterModulus: uint64(25),
		LastCounter:         uint64(0),
		BatchSize:           uint32(8 << 20),
		CounterChannel:      make(chan uint64),
		DeleteChannel:       make(chan uint64),
		Checksum:            checksum,
		AncestralMemory:     lane.NewDeque(),
		DBWriteSemaphore:    int32(0),
		brokenSnapshot:      false,
	}
	go snap.Run()

	return snap, nil
}

func (snap *Snapshot) Run() {
	glog.Infof("Snapshot.Run: Starting the run loop")
	for {
		glog.Infof("Snapshot.Run: Beginning loop iteration")
		select {
		case counter := <-snap.CounterChannel:
			{
				glog.Infof("Snapshot.Run: Flushing ancestral records with counter (%v)", counter)
				snap.FlushAncestralRecordsWithCounter()
			}
		case height := <-snap.DeleteChannel:
			{
				glog.Infof("Snapshot.Run: Getting into the delete channel with height (%v)", height)
				if height % snap.BlockHeightModulus == 0 {
					glog.Infof("Snapshot.Run: About to delete BlockHeight (%v) and set new height (%v)", snap.BlockHeight, height)
					snap.LastCounter = snap.FlushCounter
					snap.BlockHeight = height
					snap.DeleteAncestralRecords(height)
				}
			}
		}
	}
}

// PrepareAncestralRecord sets an adequate record in AncestralMap or NotExistsMap.
func (snap *Snapshot) PrepareAncestralRecord(key string, value []byte, existed bool) error {
	// If the record was not found, we add it to the NotExistsMap, otherwise to AncestralMap.
	// We record the key in MapKeyList.
	index := snap.FlushCounter

	if snap.AncestralMemory.Empty() {
		return fmt.Errorf("Snapshot.PrepareAncestralRecords: ancestral memory is empty. " +
			"Did you forget to call Snapshot.PrepareAncestralFlush?")
	}

	lastAncestralCache := snap.AncestralMemory.Last().(*AncestralCache)
	if lastAncestralCache.index != index {
		return fmt.Errorf("Snapshot.PrepareAncestralRecords: last ancestral cache index (%v) is " +
			"greater than current flush index (%v)", lastAncestralCache.index, index)
	}

	if _, ok := lastAncestralCache.AncestralMap[key]; ok {
		return nil
	}

	if _, ok := lastAncestralCache.NotExistsMap[key]; ok {
		return nil
	}

	lastAncestralCache.MapKeyList = append(lastAncestralCache.MapKeyList, key)
	if existed {
		lastAncestralCache.AncestralMap[key] = value
	} else {
		lastAncestralCache.NotExistsMap[key] = true
	}
	return nil
}

// GetCurrentPrefixAndKey is used to get an ancestral record key from a main DB key.
// 		<prefix, type [1]byte, blockHeight [10]byte, key> -> <>
func (snap *Snapshot) GetCurrentPrefixAndKey (notExistsRecord bool, key []byte) []byte {
	var prefix []byte

	// Append block height, which is the current snapshot identifier.
	prefix = append(prefix, EncodeUint64(snap.BlockHeight)...)

	// Finally, append the main DB key.
	prefix = append(prefix, key...)

	// Append prefix type at the end so that checking existence of a particular record only takes 1 lookup instead of two.
	// Append the type
	// 		0 - non-existing main DB key
	//		1 - existing main DB key
	if notExistsRecord {
		prefix = append(prefix, _PrefixNonExistentAncestralRecord...)
	} else {
		prefix = append(prefix, _PrefixExistentAncestralRecord...)
	}
	return prefix
}

func (snap *Snapshot) GetSeekPrefix (key []byte) []byte {
	var prefix []byte

	// Append block height, which is the current snapshot identifier.
	prefix = append(prefix, EncodeUint64(snap.BlockHeight)...)

	// Finally, append the main DB key.
	prefix = append(prefix, key...)
	return prefix
}

func (snap *Snapshot) SnapKeyToDBEntryKey (key []byte) []byte {
	if len(key) > 8 {
		return key[8:]
	} else {
		return key
	}
}

func (snap *Snapshot) AncestralRecordToDBEntry (ancestralEntry *DBEntry) *DBEntry {
	// TODO: copy?
	var dbKey, dbVal []byte
	if len(ancestralEntry.Key) > 8 {
		dbKey = ancestralEntry.Key[8:]
	} else {
		dbKey = ancestralEntry.Key
	}

	if len(ancestralEntry.Value) > 0 {
		dbVal = ancestralEntry.Value[:len(ancestralEntry.Value)-1]
	}
	return &DBEntry{
		Key: dbKey,
		Value: dbVal,
	}
}

func (snap *Snapshot) CheckPrefixExists (value []byte) bool {
	if len(value) > 0 {
		return value[len(value)-1] == 1
	}
	return false
}

func (snap *Snapshot) PrepareAncestralFlush() uint64 {
	// Increment snapshot semaphore counter to indicate we're about to flush.
	snap.IncrementSemaphore()

	snap.FlushCounter += 1
	index := snap.FlushCounter

	snap.AncestralMemory.Append(NewAncestralCache(index))

	glog.Infof("Snapshot.PrepareAncestralFlush: Created structs at index (%v)", index)
	// TODO: is this everything we want to do prior to a flush?
	return index
}

// FlushAncestralRecords updates the ancestral records after a utxo_view flush.
// This function should be called in a go-routine after all utxo_view flushes.
func (snap *Snapshot) FlushAncestralRecords(counter uint64) {
	// If snapshot is broken then there's nothing to do.
	glog.Infof("Snapshot.FlushAncestralRecords: Initiated the flush")
	// Decrement snapshot semaphore counter.
	atomic.AddInt32(&snap.DBWriteSemaphore, int32(-1))

	err := snap.Checksum.Wait()
	if err != nil {
		glog.Errorf("Snapshot.FlushAncestralRecords: Error while waiting for checksum: (%v)", err)
		return
	}

	if snap.brokenSnapshot {
		glog.Errorf("Snapshot.FlushAncestralRecords: Broken snapshot, aborting")
		return
	}

	glog.Infof("Snapshot.FlushAncestralRecords: Sending counter (%v) to the CounterChannel", snap.FlushCounter)
	// We send the flush counter to the counter to indicate that a flush should take place.
	snap.CounterChannel <- counter
	return
}

func (snap *Snapshot) isState(key []byte) bool {
	return isStateKey(key) && !snap.brokenSnapshot
}

// FlushAncestralRecords updates the ancestral records after a utxo_view flush.
// This function should be called in a go-routine after all utxo_view flushes.
func (snap *Snapshot) FlushAncestralRecordsWithCounter() {
	snap.DBLock.Lock()
	defer snap.DBLock.Unlock()

	// If snapshot is broken then there's nothing to do.
	glog.Infof("Snapshot.FlushAncestralRecords: Initiated the flush")
	// Decrement snapshot semaphore counter.
	atomic.AddInt32(&snap.DBWriteSemaphore, int32(-1))

	if snap.brokenSnapshot {
		glog.Errorf("Snapshot.FlushAncestralRecords: Broken snapshot, aborting")
		return
	}

	lastAncestralCache := snap.AncestralMemory.First().(*AncestralCache)

	if lastAncestralCache.index <= snap.LastCounter {
		glog.Infof("Snapshot.FlushAncestralRecords: Discarding index (%v) because it's before the last index (%v)",
			lastAncestralCache.index, snap.LastCounter)
		snap.AncestralMemory.Shift()

		return
	}

	// First sort the copyMapKeyList so that we write to BadgerDB in order.
	sort.Strings(lastAncestralCache.MapKeyList)
	glog.Infof("Snapshot.FlushAncestralRecords: Finished sorting map keys")

	// We launch a new read-write transaction to set the records.

	err := snap.Db.Update(func(txn *badger.Txn) error {
		// In case we kill the node in the middle of this update.
		err := txn.Set(_PrefixSnapshotHealth, []byte{0})
		if err != nil {
			return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem flushing " +
				"snapshot health")
		}
		// Iterate through all now-sorted keys.
		glog.Infof("Snapshot.FlushAncestralRecords: Adding (%v) new records", len(lastAncestralCache.MapKeyList))
		glog.Infof("Snapshot.FlushAncestralRecords: Adding (%v) AncestralMap records", len(lastAncestralCache.AncestralMap))
		glog.Infof("Snapshot.FlushAncestralRecords: Adding (%v) NotExistsMap records", len(lastAncestralCache.NotExistsMap))
		for _, key := range lastAncestralCache.MapKeyList {
			// We store keys as strings because they're easier to store and sort this way.
			keyBytes, err := hex.DecodeString(key)
			if err != nil {
				return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
					"decoding copyMapKeyList key: %v", key)
			}

			// We check whether this record is already present in ancestral records,
			// if so then there's nothing to do. What we want is err == badger.ErrKeyNotFound
			_, err = txn.Get(snap.GetSeekPrefix(keyBytes))
			if err != nil && err != badger.ErrKeyNotFound {
				return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
					"reading exsiting record in the DB at key: %v", key)
			}
			if err == nil {
				continue
			}

			// If we get here, it means that no record existed in ancestral records at key.
			// The key was either added to copyAncestralMap or copyNotExistsMap during flush.
			if value, exists := lastAncestralCache.AncestralMap[key]; exists {
				err = txn.Set(snap.GetSeekPrefix(keyBytes), append(value, byte(1)))
				if err != nil {
					return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
						"flushing a record from copyAncestralMap at key %v:", key)
				}
			} else if _, exists = lastAncestralCache.NotExistsMap[key]; exists {
				err = txn.Set(snap.GetSeekPrefix(keyBytes), []byte{byte(0)})
				if err != nil {
					return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem " +
						"flushing a record from copyNotExistsMap at key %v:", key)
				}
			} else {
				return fmt.Errorf("Snapshot.FlushAncestralRecords: Error, key is not " +
					"in copyAncestralMap nor copyNotExistsMap. This should never happen")
			}
		}
		err = txn.Set(_PrefixSnapshotHealth, []byte{1})
		if err != nil {
			return errors.Wrapf(err, "Snapshot.FlushAncestralRecords: Problem flushing " +
				"snapshot health")
		}
		return nil
	})
	if err != nil {
		// If any error occurred, then the snapshot is potentially broken.
		snap.brokenSnapshot = true
		glog.Errorf("Snapshot.FlushAncestralRecords: Problem flushing snapshot %v, Error %v", snap, err)
	}

	snap.AncestralMemory.Shift()
	glog.Infof("Snapshot.FlushAncestralRecords: Snapshot, finished flushing ancestral records. Snapshot " +
		"status, brokenSnapshot: (%v)", snap.brokenSnapshot)
}

func (snap *Snapshot) DeleteAncestralRecords(height uint64) {
	snap.DBLock.Lock()
	defer snap.DBLock.Unlock()

	var prefix []byte
	prefix = append(prefix, EncodeUint64(height)...)

	glog.Infof("Snapshot.DeleteAncestralRecords: Starting delete process for height (%v)", height)
	numDeleted := 0
	//maxPrint := 5
	err := snap.Db.DropPrefix(prefix)
	if err != nil {
		glog.Errorf("Snapshot.DeleteAncestralRecords: Problem deleting ancestral records error (%v)", err)
		return
	}
	glog.Infof("Snapshot.DeleteAncestralRecords: Finished deleting for height (%v) total (%v)", height, numDeleted)
}

func (snap *Snapshot) String() string {
	return fmt.Sprintf("< Snapshot | height: %v | broken: %v >", snap.BlockHeight, snap.brokenSnapshot)
}

func (snap *Snapshot) IncrementSemaphore() {
	// TODO: DON'T REALLY NEED TO CHECK THAT IF WE'RE USING THE CHANNEL
	//currentSemaphore := atomic.LoadInt32(&snap.DBWriteSemaphore)
	//if currentSemaphore > 0 {
	//	snap.brokenSnapshot = true
	//	glog.Errorf("UtxoView.FlushToDbWithTxn: Race condition in flush to snapshot, " +
	//		"current DBWriteSemaphore: %v", currentSemaphore)
	//}
	atomic.AddInt32(&snap.DBWriteSemaphore, 1)
}

// GetSnapshotChunk gets fetches a batch of records from the nodes DB that match the provided prefix
// and have a key at least equal to the startKey lexicographically. The function will also fetch ancestral
// records and combine them with the DB records so that the batch reflects an ancestral block.
func (snap *Snapshot) GetSnapshotChunk(mainDb *badger.DB, prefix []byte, startKey []byte) (
	_snapshotEntriesBatch []*DBEntry, _snapshotEntriesFilled bool, _err error) {
	// This the list of fetched DB entries.
	var snapshotEntriesBatch []*DBEntry

	// Fetch the batch from main DB records with a batch size of about snap.BatchSize.
	mainDbBatchEntries, mainDbFilled, err := DBIteratePrefixKeys(mainDb, prefix, startKey, snap.BatchSize)
	if err != nil {
		return nil, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}
	// Fetch the batch from the ancestral DB records with a batch size of about snap.BatchSize.
	ancestralDbBatchEntries, ancestralDbFilled, err := DBIteratePrefixKeys(snap.Db,
		snap.GetSeekPrefix(prefix), snap.GetSeekPrefix(startKey), snap.BatchSize)
	if err != nil {
		return nil, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}

	// To combine the main DB entries and the ancestral records DB entries, we iterate through the ancestral records and
	// for each key we add all the main DB keys that are smaller than the currently processed key. The ancestral records
	// entries have priority over the main DB entries, so whenever there are entries with the same key among the two DBs,
	// we will only add the ancestral record entry to our snapshot batch. Also, the loop below might appear like O(n^2)
	// but it's actually O(n) because the inside loop iterates at most O(n) times in total.

	// Index to keep track of how many main DB entries we've already processed.
	indexChunk := 0
	for _, ancestralEntry := range ancestralDbBatchEntries {
		dbEntry := snap.AncestralRecordToDBEntry(ancestralEntry)
		if snap.CheckPrefixExists(ancestralEntry.Value) {
			snapshotEntriesBatch = append(snapshotEntriesBatch, dbEntry)
		}

		for jj := indexChunk; jj < len(mainDbBatchEntries); {
			if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == -1 {
					snapshotEntriesBatch = append(snapshotEntriesBatch, mainDbBatchEntries[jj])
			} else if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == 1 {
				break
			}
			// if keys are equal we just skip
			jj ++
			indexChunk = jj
		}
		// If we filled the chunk for main db records, we will return so that there is no
		// gap between the most recently added DBEntry and the next ancestral record. Otherwise,
		// we will keep going with the loop and add all the ancestral records.
		if mainDbFilled && indexChunk == len(mainDbBatchEntries) {
			break
		}
	}

	// If we got all ancestral records, but there are still some main DB entries that we can add,
	// we will do that now.
	if !ancestralDbFilled {
		for jj := indexChunk; jj < len(mainDbBatchEntries); jj++ {
			indexChunk = jj
			snapshotEntriesBatch = append(snapshotEntriesBatch, mainDbBatchEntries[jj])
		}
	}

	if len(snapshotEntriesBatch) == 0 {
		snapshotEntriesBatch = append(snapshotEntriesBatch, EmptyDBEntry())
		return snapshotEntriesBatch, false, nil
	}

	// If either of the chunks is full, we should return true.
	return snapshotEntriesBatch, mainDbFilled || ancestralDbFilled, nil
}

func (snap *Snapshot) SetSnapshotChunk(mainDb *badger.DB, chunk []*DBEntry) error {
	return mainDb.Update(func(txn *badger.Txn) error {
		for _, dbEntry := range chunk {
			if dbEntry.IsEmpty() {
				glog.Infof("Server._handleSnapshot: received an empty DBEntry")
				break
			}
			// TODO: This check is important, should be re-implemented.
			_, err := txn.Get(dbEntry.Key)
			if err == nil {
				continue
			}
			if err != nil && err != badger.ErrKeyNotFound {
				return err
			}

			err = txn.Set(dbEntry.Key, dbEntry.Value)
			if err != nil {
				return err
			}
			if err := snap.Checksum.AddBytes(EncodeKeyValue(dbEntry.Key, dbEntry.Value)); err != nil {
				return errors.Wrapf(err, "DBSetWithTxn: Problem updating the checksum ")
			}
		}
		return nil
	})
}
