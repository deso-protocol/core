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
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

// -------------------------------------------------------------------------------------
// StateChecksum
// -------------------------------------------------------------------------------------

// StateChecksum is used to verify integrity of state data. When syncing state from
// peers, we need to ensure that we are receiving the same copy of the database.
// Traditionally, this has been done using Merkle trees; however, Merkle trees incur
// O(log n) computational complexity for updates and O(n) space complexity, where n
// is the number of leaves in the tree.
//
// Instead, we use a structure that allows us to have an O(1) time and O(1) space complexity. We call
// our checksum construction EllipticSum, as the checksum of the data is represented by a sum of
// elliptic curve points. To verify integrity of the data, we only need a single ec point.
//
// To put in layman's terms, the EllipticSum checksum works as follows:
// - Checksum = hash_to_curve(chunk_0) + hash_to_curve(chunk_1) + ... + hash_to_curve(chunk_n)
// where chunk_i is a chunk of bytes, and hash_to_curve(chunk_i) generates an elliptic curve point
// from the bytes deterministically, similar to hashing the bytes. The reason we sum elliptic curve
// points rather than hashes of the bytes is because summing hashes of the bytes would result in
// the checksum being vulnerable to attack, as discussed below.
//
// EllipticSum is inspired by the generalized k-sum problem, where given a set of uniformly random
// numbers L, we want to find a subset of k elements in L that XORs to 0. This XOR problem
// can actually be solved efficiently with dynamic programming, so it's not
// useful to us as a checksum if we use the naive XOR version. However, if we extend it to
// using elliptic curve points, as we explain below, it becomes computationally infeasible
// to solve, which is what we need.
//
// The reason this works is that k-sum can be generalized to any algebraic group. That is,
// given a group G, identity element 0, operation +, and some set L of random group elements, find a
// subset (a_0, a_1, ..., a_k) such that a_0 + a_1 + ... + a_k = 0.
//
// It turns out that if this is a cyclic group, such as the group formed by elliptic curve points,
// then this problem is equivalent to the DLP in G, which is computationally infeasible for a
// sufficiently large group, and which has a computational lower bound
// of O(sqrt(p)) where p is the smallest prime dividing the order of G.
// https://link.springer.com/content/pdf/10.1007%2F3-540-45708-9_19.pdf
//
// We use an elliptic curve group Ristretto255 and hash state data directly on the curve
// using the hash_to_curve primitive based on elligator2. The hash_to_curve mapping takes a
// byte array input and outputs a point via a mapping indistinguishable from a random function.
// Hash_to_curve does not reveal the discrete logarithm of the output points.
// According to the O(sqrt(p)) lower bound, Ristretto255 guarantees 126 bits of security.
//
// To learn more about hash_to_curve, see this article:
// https://tools.ietf.org/id/draft-irtf-cfrg-hash-to-curve-06.html
type StateChecksum struct {
	// curve is the Ristretto255 elliptic curve group.
	curve group.Group
	// checksum is the ec point we use for verifying integrity of state data. It represents
	// the sum of points associated with all individual db records.
	checksum group.Element
	// dst string for the hash_to_curve function. This works like a seed.
	dst []byte

	// semaphore is used to manage parallelism when computing the state checksum. We use
	// a worker pool pattern of spawning a bounded number of threads to compute the checksum
	// in parallel. This allows us to compute it much more efficiently.
	semaphore *semaphore.Weighted
	// ctx is a helper variable used by the semaphore.
	ctx context.Context

	// hashToCurveCache is a cache of computed hashToCurve mappings
	hashToCurveCache lru.KVCache

	// When we want to add a database record to the state checksum, we will first have to
	// map the record to the Ristretto255 curve using the hash_to_curve. We will then add the
	// output point to the checksum. The hash_to_curve operation is about 2-3 orders of magnitude
	// slower than the point addition, therefore we will compute the hash_to_curve in parallel
	// and then add the output points to the checksum serially while holding a mutex.
	addMutex sync.Mutex

	// maxWorkers is the maximum number of workers we can have in the worker pool.
	maxWorkers int64
}

// Initialize starts the state checksum by initializing it to the identity element.
func (sc *StateChecksum) Initialize() {
	// Set the elliptic curve group to Ristretto255 and initialize checksum as identity.
	sc.curve = group.Ristretto255
	sc.checksum = sc.curve.Identity()
	// Set the dst string.
	sc.dst = []byte("DESO-ELLIPTIC-SUM:Ristretto255")

	// Set max workers to the number of available threads.
	sc.maxWorkers = int64(runtime.GOMAXPROCS(0))

	// Set the hashToCurveCache
	sc.hashToCurveCache = lru.NewKVCache(HashToCurveCache)

	// Set the worker pool semaphore and context.
	sc.semaphore = semaphore.NewWeighted(sc.maxWorkers)
	sc.ctx = context.Background()
}

func (sc *StateChecksum) AddToChecksum(elem group.Element) {
	sc.addMutex.Lock()
	defer sc.addMutex.Unlock()

	sc.checksum.Add(sc.checksum, elem)
}

func (sc *StateChecksum) HashToCurve(bytes []byte) group.Element {
	var hashElement group.Element

	// Check if we've already mapped this element, if so we will save some computation this way.
	bytesStr := hex.EncodeToString(bytes)
	if elem, exists := sc.hashToCurveCache.Lookup(bytesStr); exists {
		hashElement = elem.(group.Element)
	} else {
		// Compute the hash_to_curve primitive, mapping  the bytes to an elliptic curve point.
		hashElement = sc.curve.HashToElement(bytes, sc.dst)
		// Also add to the hashToCurveCache
		sc.hashToCurveCache.Add(bytesStr, hashElement)
	}

	return hashElement
}

// AddBytes adds record bytes to the checksum in parallel.
func (sc *StateChecksum) AddBytes(bytes []byte) error {
	// First check if we can add another worker to the worker pool by trying to increment the semaphore.
	if err := sc.semaphore.Acquire(sc.ctx, 1); err != nil {
		return errors.Wrapf(err, "StateChecksum.AddBytes: problem acquiring semaphore")
	}

	// Spawn a go routine that will add the bytes to the checksum and then
	// decrement the semaphore.
	go func(sc *StateChecksum, bytes []byte) {
		defer sc.semaphore.Release(1)

		hashElement := sc.curve.HashToElement(bytes, sc.dst)
		// Hold the lock on addMutex to add the bytes to the checksum sequentially.
		sc.AddToChecksum(hashElement)
	}(sc, bytes)

	return nil
}

// RemoveBytes works similarly to AddBytes.
func (sc *StateChecksum) RemoveBytes(bytes []byte) error {
	// First check if we can add another worker to the worker pool by trying to increment the semaphore.
	if err := sc.semaphore.Acquire(sc.ctx, 1); err != nil {
		return errors.Wrapf(err, " StateChecksum.RemoveBytes: problem acquiring semaphore")
	}

	// Spawn a go routine that will remove the bytes from the checksum
	// and decrement the semaphore.
	go func(sc *StateChecksum, bytes []byte) {
		defer sc.semaphore.Release(1)

		// To remove bytes from the checksum, we will compute the inverse of the provided data
		// and add it to the checksum. Since the checksum is a sum of ec points, adding an inverse
		// of a previously added point will remove that point from the checksum. If we've previously
		// added point (x, y) to the checksum, we will be now adding the inverse (x, -y).
		hashElement := sc.curve.HashToElement(bytes, sc.dst)
		hashElement = hashElement.Neg(hashElement)

		// Hold the lock on addMutex to add the bytes to the checksum sequentially.
		sc.AddToChecksum(hashElement)
	}(sc, bytes)
	return nil
}

// GetChecksum is used to get the checksum elliptic curve element.
func (sc *StateChecksum) GetChecksum() (group.Element, error) {
	// To get the checksum we will wait for all the current worker threads to finish.
	// To do so, we can just try to acquire sc.maxWorkers in the semaphore.
	if err := sc.semaphore.Acquire(sc.ctx, sc.maxWorkers); err != nil {
		return nil, errors.Wrapf(err, "StateChecksum.GetChecksum: problem acquiring semaphore")
	}
	defer sc.semaphore.Release(sc.maxWorkers)

	// Also acquire the add mutex for good hygiene to make sure the checksum doesn't change.
	sc.addMutex.Lock()
	defer sc.addMutex.Unlock()

	// Clone the checksum by adding it to identity. That's faster than doing ToBytes / FromBytes
	checksumCopy := group.Ristretto255.Identity()
	checksumCopy.Add(checksumCopy, sc.checksum)

	return checksumCopy, nil
}

// Wait until there is no checksum workers holding the semaphore.
func (sc *StateChecksum) Wait() error {
	if err := sc.semaphore.Acquire(sc.ctx, sc.maxWorkers); err != nil {
		return errors.Wrapf(err, "StateChecksum.Wait: problem acquiring semaphore")
	}
	defer sc.semaphore.Release(sc.maxWorkers)
	return nil
}

// ToBytes gets the checksum point encoded in compressed format as a 32 byte array.
// Note: Don't use this function to deep copy the checksum, use GetChecksum instead.
// ToBytes is doing an inverse square root, so it is slow.
func (sc *StateChecksum) ToBytes() ([]byte, error) {
	// Get the checksum.
	checksum, err := sc.GetChecksum()
	if err != nil {
		return nil, errors.Wrapf(err, "StateChecksum.ToBytes: problem getting checksum")
	}

	// Encode checksum to bytes.
	checksumBytes, err := checksum.MarshalBinary()
	if err != nil {
		return nil, errors.Wrapf(err, "stateChecksum.ToBytes: error during MarshalBinary")
	}
	return checksumBytes, nil
}

// -------------------------------------------------------------------------------------
// DBEntry
// -------------------------------------------------------------------------------------

// DBEntry is used to represent a database record. It's more convenient than passing
// <key, value> everywhere.
type DBEntry struct {
	Key   []byte
	Value []byte
}

func (entry *DBEntry) ToBytes() []byte {
	data := []byte{}

	data = append(data, EncodeByteArray(entry.Key)...)
	data = append(data, EncodeByteArray(entry.Value)...)
	return data
}

func (entry *DBEntry) FromBytes(rr *bytes.Reader) error {
	var err error

	// Decode key.
	entry.Key, err = DecodeByteArray(rr)
	if err != nil {
		return err
	}

	// Decode value.
	entry.Value, err = DecodeByteArray(rr)
	if err != nil {
		return err
	}

	return nil
}

// KeyValueToDBEntry is used to instantiate db entry from a <key, value> pair.
func KeyValueToDBEntry(key []byte, value []byte) *DBEntry {
	dbEntry := &DBEntry{}
	// Encode the key.
	dbEntry.Key = make([]byte, len(key))
	copy(dbEntry.Key, key)

	// Encode the value.
	dbEntry.Value = make([]byte, len(value))
	copy(dbEntry.Value, value)

	return dbEntry
}

// EmptyDBEntry indicates an empty DB entry. It's used for convenience.
func EmptyDBEntry() *DBEntry {
	// We do not use prefix 0 for state so we can use it in the empty DBEntry.
	return &DBEntry{
		Key:   []byte{0},
		Value: []byte{},
	}
}

// IsEmpty return true if the DBEntry is empty, false otherwise.
func (entry *DBEntry) IsEmpty() bool {
	return bytes.Equal(entry.Key, []byte{0})
}

// -------------------------------------------------------------------------------------
// Snapshot
// -------------------------------------------------------------------------------------

// List of database prefixes corresponding to the snapshot database.
var (
	// Prefix to store ancestral records. Ancestral records represent historical
	// values of main db entries that were modified during a snapshot epoch. For
	// instance if we modified some record <key, value> -> <key, value_new> in
	// the main db, we will store <key, value> in the ancestral records under:
	//  <prefix [1]byte, blockheight [8]byte, key []byte> -> <value []byte, existence_byte [1]byte>
	// The existence_byte is either 0 or 1 depending on whether <key, value>
	// previously existed in the main db. The existence_byte allows us to quickly
	// determine if a given record existed in a snapshot without making additional
	// lookups. It is part of the value, instead of the key, so that we can confirm
	// that a given key has already been saved to the ancestral records by performing
	// just a single lookup. If it was part of the key, we would have needed two.
	_prefixAncestralRecord = []byte{0}

	// Last Snapshot epoch metadata prefix is used to encode information about the last snapshot epoch.
	// This includes the SnapshotBlockHeight, CurrentEpochChecksumBytes, CurrentEpochBlockHash.
	// 	<prefix [1]byte> -> <SnapshotEpochMetadata>
	_prefixLastEpochMetadata = []byte{1}

	// This prefix saves the checksum bytes after a flush.
	// 	<prefix [1]byte> -> <checksum bytes [33]byte>
	_prefixSnapshotChecksum = []byte{2}
)

type SnapshotEpochMetadata struct {
	// SnapshotBlockHeight is the height of the snapshot.
	SnapshotBlockHeight uint64

	// CurrentEpochChecksumBytes is the bytes of the state checksum for the snapshot at the epoch.
	CurrentEpochChecksumBytes []byte
	// CurrentEpochBlockHash is the hash of the first block of the current epoch. It's used to identify the snapshot.
	CurrentEpochBlockHash *BlockHash
}

func (metadata *SnapshotEpochMetadata) ToBytes() []byte {
	var data []byte

	data = append(data, UintToBuf(metadata.SnapshotBlockHeight)...)
	data = append(data, EncodeByteArray(metadata.CurrentEpochChecksumBytes)...)
	data = append(data, EncodeByteArray(metadata.CurrentEpochBlockHash.ToBytes())...)

	return data
}

func (metadata *SnapshotEpochMetadata) FromBytes(rr *bytes.Reader) error {
	var err error

	metadata.SnapshotBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return err
	}

	metadata.CurrentEpochChecksumBytes, err = DecodeByteArray(rr)
	if err != nil {
		return err
	}

	blockHashBytes, err := DecodeByteArray(rr)
	if err != nil {
		return err
	}
	metadata.CurrentEpochBlockHash = NewBlockHash(blockHashBytes)

	return nil
}

type AncestralRecordValue struct {
	// The value we're setting for an ancestral record.
	Value []byte

	// This is true if the key we're modifying had a pre-existing
	// value in our state. For example, we if we are updating a profile
	// then we might have a pre-existing entry for the pubkey->profile
	// mapping that we're updating. When this value is false, it means
	// we're setting a key that didn't have an associated value in our
	// state previously.
	Existed bool
}

// AncestralCache is an in-memory structure that helps manage concurrency between node's
// main db flushes and ancestral records flushes. For each main db flush transaction, we
// will build an ancestral cache that contains maps of historical values that were in the
// main db before we flushed. In particular, we distinguish between existing and
// non-existing records. Existing records are those records that had already been present
// in the main db prior to the flush. Non-existing records were not present in the main db,
// and the flush added them for the first time.
//
// The AncestralCache is stored in the Snapshot struct in a concurrency-safe deque (bi-directional
// queue). This deque follows a pub-sub pattern where the main db thread pushes ancestral
// caches onto the deque. The snapshot thread then consumes these objects and writes to the
// ancestral records. We decided to use this pattern because it doesn't slow down the main
// block processing thread. However, to make this fully work, we also need some bookkeeping
// to ensure the ancestral record flushes are up-to-date with the main db flushes. We
// solve this with non-blocking counters (MainDBSemaphore, AncestralDBSemaphore) that count
// the total number of flushes to main db and ancestral records.
type AncestralCache struct {
	// id is used to identify the AncestralCache
	id uint64

	// ExistingRecordsMap keeps track of original main db of records that we modified during
	// UtxoView flush, which is where we're modifying state data. A record for a particular
	// key was either already existing in our state, or not already existing in our state.
	//
	// We store keys as strings because they're easier to store and sort this way.
	AncestralRecordsMap map[string]*AncestralRecordValue
}

func NewAncestralCache(id uint64) *AncestralCache {
	return &AncestralCache{
		id:                  id,
		AncestralRecordsMap: make(map[string]*AncestralRecordValue),
	}
}

// SnapshotOperationType define the different operations that can be enqueued to the snapshot's OperationChannel.
type SnapshotOperationType uint8

const (
	// SnapshotOperationFlush operation enqueues a flush to the ancestral records.
	SnapshotOperationFlush SnapshotOperationType = iota
	// SnapshotOperationProcessBlock operation signals that a new block has been added to the blockchain.
	SnapshotOperationProcessBlock
	// SnapshotOperationProcessChunk operation is enqueued when we receive a snapshot chunk during syncing.
	SnapshotOperationProcessChunk
	// SnapshotOperationChecksumAdd operation is enqueued when we want to add bytes to the state checksum.
	SnapshotOperationChecksumAdd
	// SnapshotOperationChecksumRemove operation is enqueued when we want to remove bytes to the state checksum.
	SnapshotOperationChecksumRemove
	// SnapshotOperationChecksumPrint is called when we want to print the state checksum.
	SnapshotOperationChecksumPrint
	// SnapshotOperationExit is used to quit the snapshot loop
	SnapshotOperationExit
)

// SnapshotOperation is passed in the snapshot's OperationChannel.
type SnapshotOperation struct {
	// operationType determines the operation.
	operationType SnapshotOperationType

	/* SnapshotOperationProcessBlock */
	// blockNode is the processed block.
	blockNode *BlockNode

	/* SnapshotOperationProcessChunk */
	// mainDb is the main db instance.
	mainDb *badger.DB
	// snapshotChunk is the snapshot chunk received from the peer.
	snapshotChunk []*DBEntry

	/* SnapshotOperationChecksumAdd, SnapshotOperationChecksumRemove */
	// checksumBytes is the bytes we want to add to the checksum, passed during
	checksumBytes []byte

	/* SnapshotOperationChecksumPrint */
	// printText is the text we want to put in the print statement.
	printText string
}

// Snapshot is the main data structure used in hyper sync. It manages the creation of the database
// snapshot (as the name suggests), which is a periodic copy of the node's state at certain block
// heights, separated by a constant period. This period is defined by SnapshotBlockHeightPeriod,
// meaning Snapshot will build copies of the db at heights: 0, period, 2 * period, 3 * period, ...
// The blocks between the snapshot heights are referred to as a snapshot epoch.
//
// Cloning the database for infinite-state blockchains like DeSo would be extremely costly,
// incurring minutes of downtime. Using merkle trees is also out of the question because
// Merkle trees incur O(log n) computational complexity for updates and O(n) space complexity,
// where n is the number of leaves in the tree.
//
// Instead, we use a structure called ancestral records, combined with a breakthrough checksum
// mechanism called EllipticSum. Ancestral records are constructed on-the-go and only store
// records modified during a snapshot epoch. This allows
// us to reconstruct the database at the last snapshot height by combining the ancestral record
// entries with the main db entries. This process has a significantly smaller computational and
// storage overhead.
//
// The ancestral records are stored in a separate database that's modified
// asynchronously to the main db. This means that the main node thread is minimally affected by
// the snapshot computation. It also means that we need to manage the concurrency between these two
// databases. We will achieve this without locking through Snapshot's OperationChannel, to which
// the main thread will enqueue asynchronous operations such as ancestral record updates, checksum
// computations, snapshot operations, etc. In addition, Snapshot is used to serve state chunks
// to nodes that are booting using hyper sync. In such cases, the Snapshot will fetch a portion
// of the snapshot database by scanning a section of the main db as well as relevant ancestral
// records, to combine them into a chunk representing the database at a past snapshot heights.
//
// Summarizing, Snapshot serves three main purposes:
// 	- maintaining ancestral records
// 	- managing the state checksum
// 	- serving snapshot chunks to syncing nodes.
type Snapshot struct {
	// SnapshotDb is used to store snapshot-related records.
	SnapshotDb *badger.DB
	// AncestralMemory stores information about the ancestral records that should be flushed into the db.
	// We use a concurrency-safe deque which allows us to push objects to the end of the AncestralMemory
	// queue in one thread and consume objects from the beginning of the queue in another thread without
	// concurrency issues. The objects that we push to the queue will be instances of AncestralCache.
	AncestralMemory *lane.Deque

	// DatabaseCache is used to store most recent DB records that we've read/written.
	// This is a low-level optimization for ancestral records that
	// saves us read time when we're writing to the DB during UtxoView flush.
	DatabaseCache lru.KVCache

	// AncestralFlushCounter is used to offset ancestral records flush to occur only after x blocks.
	AncestralFlushCounter uint64

	// SnapshotBlockHeightPeriod is the constant height offset between individual snapshot epochs.
	SnapshotBlockHeightPeriod uint64

	// OperationChannel is used to enqueue actions to the main snapshot Run loop. It is used to
	// schedule actions such as ancestral records updates, checksum computation, snapshot operations.
	OperationChannel chan *SnapshotOperation

	// Checksum allows us to confirm integrity of the state so that when we're syncing with peers,
	// we are confident that data wasn't tampered with.
	Checksum *StateChecksum

	// CurrentEpochSnapshotMetadata is the information about the currently stored complete snapshot, which
	// reflects the state of the blockchain at the largest height divisible by SnapshotBlockHeightPeriod.
	// The metadata includes the block height and its block hash of when the snapshot was taken, and the
	// state checksum.
	CurrentEpochSnapshotMetadata *SnapshotEpochMetadata

	// MainDBSemaphore and AncestralDBSemaphore are atomically accessed counter semaphores that will be
	// used to control race conditions between main db and ancestral records.
	MainDBSemaphore      int32
	AncestralDBSemaphore int32
	// SemaphoreLock is held whenever we modify the MainDBSemaphore or AncestralDBSemaphore.
	SemaphoreLock sync.Mutex

	// brokenSnapshot indicates that we need to rebuild entire snapshot from scratch.
	// Updates to the snapshot happen in the background, so sometimes they can be broken
	// if a node stops unexpectedly. Health checks will detect these and set brokenSnapshot.
	brokenSnapshot bool

	isTxIndex       bool
	disableChecksum bool

	// ExitChannel is used to stop the snapshot when shutting down the node.
	ExitChannel chan bool
	// updateWaitGroup is used to wait for snapshot loop to finish.
	updateWaitGroup sync.WaitGroup

	timer *Timer
}

// NewSnapshot creates a new snapshot instance.
func NewSnapshot(dataDirectory string, snapshotBlockHeightPeriod uint64, isTxIndex bool,
	disableChecksum bool) (*Snapshot, error) {
	// TODO: make sure we don't snapshot when using PG
	// Initialize the ancestral records database
	snapshotDir := filepath.Join(GetBadgerDbPath(dataDirectory), "snapshot")
	snapshotOpts := badger.DefaultOptions(snapshotDir)
	snapshotOpts.ValueDir = GetBadgerDbPath(snapshotDir)
	snapshotOpts.MemTableSize = 2000 << 20
	snapshotDb, err := badger.Open(snapshotOpts)
	if err != nil {
		glog.Fatal(err)
	}
	glog.Infof("Snapshot BadgerDB Dir: %v", snapshotOpts.Dir)
	glog.Infof("Snapshot BadgerDB ValueDir: %v", snapshotOpts.ValueDir)
	if snapshotBlockHeightPeriod == 0 {
		snapshotBlockHeightPeriod = SnapshotBlockHeightPeriod
	}

	// Initialize the checksum.
	checksum := &StateChecksum{}
	checksum.Initialize()

	// Retrieve the snapshot epoch metadata from the snapshot db.
	metadata := &SnapshotEpochMetadata{
		SnapshotBlockHeight:       uint64(0),
		CurrentEpochChecksumBytes: []byte{},
		CurrentEpochBlockHash:     NewBlockHash([]byte{}),
	}
	err = snapshotDb.View(func(txn *badger.Txn) error {
		// Get the snapshot checksum first.
		item, err := txn.Get(_prefixSnapshotChecksum)
		if err != nil {
			return err
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		// If we get here, it means we've saved a checksum in the db, so we will set it to the checksum.
		err = checksum.checksum.UnmarshalBinary(value)
		if err != nil {
			return err
		}

		// Now get the last epoch metadata.
		item, err = txn.Get(_prefixLastEpochMetadata)
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		rr := bytes.NewReader(value)
		return metadata.FromBytes(rr)
	})
	// If we're starting the hyper sync node for the first time, then there will be no snapshot saved
	// and we'll get ErrKeyNotFound error. That's why we don't error when it happens.
	if err != nil && err != badger.ErrKeyNotFound {
		return nil, errors.Wrapf(err, "Snapshot.NewSnapshot: Problem retrieving snapshot information from db")
	}
	metadata.SnapshotBlockHeight = uint64(114000)
	bb, _ := hex.DecodeString("0000000000002418ed24a2ea4b1a75c7367225a856e35ab7ff11bb7b65a86f22")
	metadata.CurrentEpochBlockHash = NewBlockHash(bb)
	metadata.CurrentEpochChecksumBytes = []byte{144, 10, 88, 174, 109, 212, 184, 207, 60, 207, 144, 79, 213, 75, 201, 81, 201, 36, 203, 177, 98, 214, 137, 87, 28, 136, 88, 43, 123, 182, 46, 111}

	// Initialize the timer.
	timer := &Timer{}
	timer.Initialize()

	// Set the snapshot.
	snap := &Snapshot{
		SnapshotDb:                   snapshotDb,
		DatabaseCache:                lru.NewKVCache(DatabaseCacheSize),
		AncestralFlushCounter:        uint64(0),
		SnapshotBlockHeightPeriod:    snapshotBlockHeightPeriod,
		OperationChannel:             make(chan *SnapshotOperation, 100000),
		Checksum:                     checksum,
		CurrentEpochSnapshotMetadata: metadata,
		AncestralMemory:              lane.NewDeque(),
		MainDBSemaphore:              int32(0),
		AncestralDBSemaphore:         int32(0),
		brokenSnapshot:               false,
		isTxIndex:                    isTxIndex,
		disableChecksum:              disableChecksum,
		timer:                        timer,
		ExitChannel:                  make(chan bool),
	}
	// Run the snapshot main loop.
	go snap.Run()

	return snap, nil
}

// Run is the snapshot main loop. It handles the operations from the OperationChannel.
func (snap *Snapshot) Run() {
	glog.V(1).Infof("Snapshot.Run: Starting update thread")

	snap.updateWaitGroup.Add(1)
	for {
		operation := <-snap.OperationChannel
		switch operation.operationType {
		case SnapshotOperationFlush:
			glog.V(1).Infof("Snapshot.Run: Flushing ancestral records with counter")
			snap.FlushAncestralRecords()

		case SnapshotOperationProcessBlock:
			glog.V(1).Infof("Snapshot.Run: Getting into the process block with height (%v)",
				operation.blockNode.Height)
			snap.SnapshotProcessBlock(operation.blockNode)

		case SnapshotOperationProcessChunk:
			glog.Infof("Snapshot.Run: Number of operations in the operation channel (%v)", len(snap.OperationChannel))
			if err := snap.SetSnapshotChunk(operation.mainDb, operation.snapshotChunk); err != nil {
				glog.Errorf("Snapshot.Run: Problem adding snapshot chunk to the db")
			}

		case SnapshotOperationChecksumAdd:
			if err := snap.Checksum.AddBytes(operation.checksumBytes); err != nil {
				glog.Errorf("Snapshot.Run: Problem adding checksum bytes operation (%v)", operation)
			}

		case SnapshotOperationChecksumRemove:
			if err := snap.Checksum.RemoveBytes(operation.checksumBytes); err != nil {
				glog.Errorf("Snapshot.Run: Problem removing checksum bytes operation (%v)", operation)
			}

		case SnapshotOperationChecksumPrint:
			stateChecksum, err := snap.Checksum.ToBytes()
			if err != nil {
				glog.Errorf("Snapshot.Run: Problem getting checksum bytes (%v)", err)
			}
			glog.V(1).Infof("Snapshot.Run: PrintText (%s) Current checksum (%v)", operation.printText, stateChecksum)
			glog.V(1).Infof("Snapshot.Run: Number of operations in the operation channel: (%v)", len(snap.OperationChannel))

		case SnapshotOperationExit:
			if err := snap.Checksum.Wait(); err != nil {
				glog.Errorf("Snapshot.Run: Problem waiting for the checksum, error (%v)", err)
			}
			snap.updateWaitGroup.Done()
			return
		}
	}
}

func (snap *Snapshot) Stop() {
	glog.V(1).Infof("Snapshot.Stop: Stopping the run loop")

	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationExit,
	}
	snap.updateWaitGroup.Wait()

	snap.SnapshotDb.Close()
}

// StartAncestralRecordsFlush updates the ancestral records after a UtxoView flush.
// This function should be called in a go-routine after all UtxoView flushes.
func (snap *Snapshot) StartAncestralRecordsFlush() {
	// If snapshot is broken then there's nothing to do.
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Initiated the flush")

	if snap.brokenSnapshot {
		glog.Errorf("Snapshot.StartAncestralRecordsFlush: Broken snapshot, aborting")
		return
	}

	// Signal that the main db update has finished by incrementing the main semaphore.
	// Also signal that the ancestral db write started by increasing the ancestral semaphore.
	snap.SemaphoreLock.Lock()
	snap.MainDBSemaphore += 1
	snap.AncestralDBSemaphore += 1
	snap.SemaphoreLock.Unlock()
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Sending counter (%v) to the CounterChannel", snap.AncestralFlushCounter)
	// We send the flush counter to the counter to indicate that a flush should take place.
	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationFlush,
	}
}

func (snap *Snapshot) PrintChecksum(text string) {
	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationChecksumPrint,
		printText:     text,
	}
}

func (snap *Snapshot) FinishProcessBlock(blockNode *BlockNode) {
	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationProcessBlock,
		blockNode:     blockNode,
	}
}

func (snap *Snapshot) ProcessSnapshotChunk(mainDb *badger.DB, snapshotChunk []*DBEntry) {
	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationProcessChunk,
		mainDb:        mainDb,
		snapshotChunk: snapshotChunk,
	}
}

func (snap *Snapshot) AddChecksumBytes(bytes []byte) {
	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationChecksumAdd,
		checksumBytes: bytes,
	}
}

func (snap *Snapshot) RemoveChecksumBytes(bytes []byte) {
	snap.OperationChannel <- &SnapshotOperation{
		operationType: SnapshotOperationChecksumRemove,
		checksumBytes: bytes,
	}
}

// WaitForAllOperationsToFinish will busy-wait for the snapshot channel to process all
// current operations. Spinlocks are undesired but it's the easiest solution in this case,
func (snap *Snapshot) WaitForAllOperationsToFinish() {
	// FIXME: Spin waiting is bad
	for {
		if len(snap.OperationChannel) > 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		break
	}
}

// PrepareAncestralRecordsFlush adds a new instance of ancestral cache to the AncestralMemory deque.
// It must be called prior to calling StartAncestralRecordsFlush.
func (snap *Snapshot) PrepareAncestralRecordsFlush() {
	// Signal that the main db update has started by incrementing the main semaphore.
	snap.SemaphoreLock.Lock()
	// If the value of MainDBSemaphore is odd, then it means we're nesting calls to
	// PrepareAncestralRecordsFlush()
	if snap.MainDBSemaphore%2 != 0 {
		glog.Fatalf("Nested calls to PrepareAncestralRecordsFlush() " +
			"detected. Make sure you call StartAncestralRecordsFlush before " +
			"calling PrepareAncestralRecordsFlush() again")
	}

	snap.MainDBSemaphore += 1
	snap.SemaphoreLock.Unlock()

	snap.AncestralFlushCounter += 1
	index := snap.AncestralFlushCounter

	snap.AncestralMemory.Append(NewAncestralCache(index))

	glog.V(1).Infof("Snapshot.PrepareAncestralRecordsFlush: Created structs at index (%v)", index)
}

// PrepareAncestralRecord prepares an individual ancestral record in the last ancestral cache.
// It will add the record to AncestralRecordsMap with a bool indicating whether the key existed
// before or not.
func (snap *Snapshot) PrepareAncestralRecord(key string, value []byte, existed bool) error {
	// If the record was not found, we add it to the NonExistingRecordsMap, otherwise to ExistingRecordsMap.
	index := snap.AncestralFlushCounter

	if snap.AncestralMemory.Empty() {
		return fmt.Errorf("Snapshot.PrepareAncestralRecord: ancestral memory is empty. " +
			"Did you forget to call Snapshot.PrepareAncestralRecordsFlush?")
	}

	// Get the last ancestral cache. This is where we'll add the new record.
	lastAncestralCache := snap.AncestralMemory.Last().(*AncestralCache)
	if lastAncestralCache.id != index {
		return fmt.Errorf("Snapshot.PrepareAncestralRecords: last ancestral cache index (%v) is "+
			"greater than current flush index (%v)", lastAncestralCache.id, index)
	}

	// If the record already exists in the ancestral cache, skip.
	if _, ok := lastAncestralCache.AncestralRecordsMap[key]; ok {
		return nil
	}

	// Add the record to the records key list and the adequate records list.
	lastAncestralCache.AncestralRecordsMap[key] = &AncestralRecordValue{
		Value:   value,
		Existed: existed,
	}
	return nil
}

// GetAncestralRecordsKey is used to get an ancestral record key from a main DB key.
// 	<prefix [1]byte, block height [8]byte, key []byte> -> <value []byte, existence_byte [1]byte>
func (snap *Snapshot) GetAncestralRecordsKey(key []byte) []byte {
	var prefix []byte

	// Append the ancestral records prefix.
	prefix = append(prefix, _prefixAncestralRecord...)

	// Append block height, which is the current snapshot identifier.
	prefix = append(prefix, EncodeUint64(snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight)...)

	// Finally, append the main DB key.
	prefix = append(prefix, key...)
	return prefix
}

// DBSetAncestralRecordWithTxn sets a record corresponding to our ExistingRecordsMap.
// We append a []byte{1} to the end to indicate that this is an existing record, and
// we append a []byte{0} to the end to indicate that this is a NON-existing record. We
// need to create this distinction to tell the difference between a record that was
// updated to have an *empty* value vs a record that was deleted entirely.
func (snap *Snapshot) DBSetAncestralRecordWithTxn(
	txn *badger.Txn, keyBytes []byte, value *AncestralRecordValue) error {

	if value.Existed {
		return txn.Set(snap.GetAncestralRecordsKey(keyBytes), append(value.Value, byte(1)))
	} else {
		return txn.Set(snap.GetAncestralRecordsKey(keyBytes), []byte{byte(0)})
	}
}

// AncestralRecordToDBEntry is used to translate the <ancestral_key, ancestral_value> pairs into
// the actual <key, value> pairs. Ancestral records have the format:
// 	<prefix [1]byte, block height [8]byte, key []byte> -> <value []byte, existence_byte [1]byte>
// So we need to trim the first 9 bytes off of the ancestral_key to get the actual key.
// And we need to trim the last 1 byte off of the ancestral_value to get the actual value.
func (snap *Snapshot) AncestralRecordToDBEntry(ancestralEntry *DBEntry) *DBEntry {
	var dbKey, dbVal []byte
	// Trim the prefix and the block height from the ancestral record key.
	dbKey = ancestralEntry.Key[9:]

	// Trim the existence_byte from the ancestral record value.
	if len(ancestralEntry.Value) > 0 {
		dbVal = ancestralEntry.Value[:len(ancestralEntry.Value)-1]
	}
	return &DBEntry{
		Key:   dbKey,
		Value: dbVal,
	}
}

// CheckAnceststralRecordExistenceByte checks the existence_byte in the ancestral record value.
func (snap *Snapshot) CheckAnceststralRecordExistenceByte(value []byte) bool {
	if len(value) > 0 {
		return value[len(value)-1] == 1
	}
	return false
}

// SnapshotProcessBlock updates the snapshot information after a block has been added.
func (snap *Snapshot) SnapshotProcessBlock(blockNode *BlockNode) {
	height := uint64(blockNode.Height)

	if height%snap.SnapshotBlockHeightPeriod == 0 {
		var err error
		glog.V(1).Infof("Snapshot.SnapshotProcessBlock: About to delete SnapshotBlockHeight (%v) and set new height (%v)",
			snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight, height)
		snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight = height
		snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes, err = snap.Checksum.ToBytes()
		if err != nil {
			glog.Errorf("Snapshot.SnapshotProcessBlock: Problem getting checksum bytes (%v)", err)
		}
		snap.CurrentEpochSnapshotMetadata.CurrentEpochBlockHash = blockNode.Hash

		// Update the snapshot epoch metadata in the snapshot DB.
		err = snap.SnapshotDb.Update(func(txn *badger.Txn) error {
			return txn.Set(_prefixLastEpochMetadata, snap.CurrentEpochSnapshotMetadata.ToBytes())
		})
		if err != nil {
			snap.brokenSnapshot = true
			glog.Errorf("Snapshot.SnapshotProcessBlock: Problem setting snapshot epoch metadata in snapshot db")
		}

		glog.V(1).Infof("Snapshot.SnapshotProcessBlock: snapshot checksum is (%v)",
			snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes)

		// TODO: This should remove past height not current height?
		snap.DeleteAncestralRecords(height)
	}
}

// isState determines if a key is a state-related record.
func (snap *Snapshot) isState(key []byte) bool {
	if !snap.isTxIndex {
		return isStateKey(key) && !snap.brokenSnapshot
	} else {
		return (isStateKey(key) || isTxIndexKey(key)) && !snap.brokenSnapshot
	}
}

// isFlushing checks whether a main DB flush or ancestral record flush is taking place.
func (snap *Snapshot) isFlushing() bool {
	// We retrieve the ancestral record and main db semaphores.
	snap.SemaphoreLock.Lock()
	ancestralDBSemaphore := snap.AncestralDBSemaphore
	mainDBSemaphore := snap.MainDBSemaphore
	snap.SemaphoreLock.Unlock()

	// Flush is taking place if the semaphores have different counters or if they are odd.
	// We increment each semaphore whenever we start the flush and when we end it so they are always
	// even when the DB is not being updated.
	return ancestralDBSemaphore != mainDBSemaphore ||
		(ancestralDBSemaphore|mainDBSemaphore)%2 == 1
}

// FlushAncestralRecords updates the ancestral records after a UtxoView flush.
// This function should be called in a go-routine after all UtxoView flushes.
func (snap *Snapshot) FlushAncestralRecords() {
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Initiated the flush")

	// If snapshot is broken then there's nothing to do.
	if snap.brokenSnapshot {
		glog.Errorf("Snapshot.StartAncestralRecordsFlush: Broken snapshot, aborting")
		return
	}

	// Make sure we've finished all checksum computation before we proceed with the flush.
	// Since this gets called after all snapshot operations are enqueued after the main db
	// flush, the order of operations is preserved; however, there could still be some
	// snapshot worker threads running so we want to wait until they're done.
	err := snap.Checksum.Wait()
	if err != nil {
		glog.Errorf("Snapshot.StartAncestralRecordsFlush: Error while waiting "+
			"for checksum: (%v)", err)
		return
	}

	// Pull items off of the deque for writing.
	lastAncestralCache := snap.AncestralMemory.First().(*AncestralCache)
	// First sort the keys so that we write to BadgerDB in order.
	recordsKeyList := make([]string, 0, len(lastAncestralCache.AncestralRecordsMap))
	for kk, _ := range lastAncestralCache.AncestralRecordsMap {
		recordsKeyList = append(recordsKeyList, kk)
	}
	sort.Strings(recordsKeyList)
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Finished sorting map keys")

	// We launch a new read-write transaction to set the records.
	err = snap.SnapshotDb.Update(func(txn *badger.Txn) error {
		// This update is called after a change to the main db records and so the current checksum reflects the state of
		// the main db. In case we restart the node, we want to be able to retrieve the most recent checksum and resume
		// from it when adding new records. Therefore, we save the current checksum bytes in the db.
		currentChecksum, err := snap.Checksum.ToBytes()
		if err != nil {
			return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem getting checksum bytes")
		}
		err = txn.Set(_prefixSnapshotChecksum, currentChecksum)
		if err != nil {
			return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem flushing checksum bytes")
		}
		// Iterate through all now-sorted keys.
		glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Adding (%v) new records", len(recordsKeyList))
		glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Adding (%v) ancestral records", len(lastAncestralCache.AncestralRecordsMap))
		for _, key := range recordsKeyList {
			// We store keys as strings because they're easier to store and sort this way.
			keyBytes, err := hex.DecodeString(key)
			if err != nil {
				return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem "+
					"decoding copyMapKeyList key: %v", key)
			}

			// We check whether this record is already present in ancestral records,
			// if so then there's nothing to do. What we want is err == badger.ErrKeyNotFound
			_, err = txn.Get(snap.GetAncestralRecordsKey(keyBytes))
			if err != badger.ErrKeyNotFound {
				if err != nil {
					// In this case, we hit a real error with Badger, so we should return.
					return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem "+
						"reading exsiting record in the DB at key: %v", key)
				} else {
					// In this case, there was no error, which means the key already exists.
					// No need to set it in that case.
					continue
				}
			}

			// If we get here, it means that no record existed in ancestral records at key,
			// so we set it here.
			value, exists := lastAncestralCache.AncestralRecordsMap[key]
			if !exists {
				return fmt.Errorf("Snapshot.StartAncestralRecordsFlush: Error, key is not " +
					"in AncestralRecordsMap. This should never happen")
			}
			err = snap.DBSetAncestralRecordWithTxn(txn, keyBytes, value)
			if err != nil {
				return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem "+
					"flushing a record from copyAncestralMap at key %v:", key)
			}
		}
		return nil
	})
	if err != nil {
		// If any error occurred, then the snapshot is potentially broken.
		snap.brokenSnapshot = true
		glog.Errorf("Snapshot.StartAncestralRecordsFlush: Problem flushing snapshot %v, Error %v", snap, err)
	}

	// Signal that the ancestral db write has finished by incrementing the semaphore.
	snap.SemaphoreLock.Lock()
	snap.AncestralDBSemaphore += 1
	snap.SemaphoreLock.Unlock()
	snap.AncestralMemory.Shift()
	glog.V(1).Infof("Snapshot.StartAncestralRecordsFlush: finished flushing ancestral records. Snapshot "+
		"status, brokenSnapshot: (%v)", snap.brokenSnapshot)
}

// DeleteAncestralRecords is used to delete ancestral records for the provided height.
func (snap *Snapshot) DeleteAncestralRecords(height uint64) {

	var prefix []byte
	prefix = append(prefix, EncodeUint64(height)...)

	glog.V(2).Infof("Snapshot.DeleteAncestralRecords: Starting delete process for height (%v)", height)
	numDeleted := 0
	err := snap.SnapshotDb.DropPrefix(prefix)
	if err != nil {
		glog.Errorf("Snapshot.DeleteAncestralRecords: Problem deleting ancestral records error (%v)", err)
		return
	}
	glog.V(2).Infof("Snapshot.DeleteAncestralRecords: Finished deleting for height (%v) total (%v)", height, numDeleted)
}

func (snap *Snapshot) String() string {
	return fmt.Sprintf("< Snapshot | height: %v | broken: %v >",
		snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight, snap.brokenSnapshot)
}

// GetSnapshotChunk fetches a batch of records from the nodes DB that match the provided prefix and
// have a key at least equal to the startKey lexicographically. The function will also fetch ancestral
// records and combine them with the DB records so that the batch reflects an ancestral block.
func (snap *Snapshot) GetSnapshotChunk(mainDb *badger.DB, prefix []byte, startKey []byte) (
	_snapshotEntriesBatch []*DBEntry, _snapshotEntriesFilled bool, _concurrencyFault bool, _err error) {

	// Check if we're flushing to the main db or to the ancestral records. If a flush is currently
	// taking place, we will return a concurrencyFault error because the records are getting modified.
	snap.SemaphoreLock.Lock()
	ancestralDBSemaphoreBefore := snap.AncestralDBSemaphore
	mainDBSemaphoreBefore := snap.MainDBSemaphore
	snap.SemaphoreLock.Unlock()
	if snap.isFlushing() {
		return nil, false, true, nil
	}

	// This the list of fetched DB entries.
	var snapshotEntriesBatch []*DBEntry

	// Fetch the batch from main DB records with a batch size of about snap.BatchSize.
	mainDbBatchEntries, mainDbFilled, err := DBIteratePrefixKeys(mainDb, prefix, startKey, SnapshotBatchSize)
	if err != nil {
		return nil, false, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}
	// Fetch the batch from the ancestral DB records with a batch size of about snap.BatchSize.
	ancestralDbBatchEntries, ancestralDbFilled, err := DBIteratePrefixKeys(snap.SnapshotDb,
		snap.GetAncestralRecordsKey(prefix), snap.GetAncestralRecordsKey(startKey), SnapshotBatchSize)
	if err != nil {
		return nil, false, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}

	// To combine the main DB entries and the ancestral records DB entries, we iterate through the
	// ancestral records and for each key we add all the main DB keys that are smaller than the
	// currently processed key. The ancestral records entries have priority over the main DB entries,
	// so whenever there are entries with the same key among the two DBs, we will only add the
	// ancestral record entry to our snapshot batch. Also, the loop below might appear like O(n^2)
	// but it's actually O(n) because the inside loop iterates at most O(n) times in total.

	// Index to keep track of how many main DB entries we've already processed.
	indexChunk := 0
	for _, ancestralEntry := range ancestralDbBatchEntries {
		//var entriesToAppend []*DBEntry

		dbEntry := snap.AncestralRecordToDBEntry(ancestralEntry)

		for jj := indexChunk; jj < len(mainDbBatchEntries); {
			if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == -1 {
				snapshotEntriesBatch = append(snapshotEntriesBatch, mainDbBatchEntries[jj])
			} else if bytes.Compare(mainDbBatchEntries[jj].Key, dbEntry.Key) == 1 {
				break
			}
			// if keys are equal we just skip
			jj++
			indexChunk = jj
		}

		//for _, entry := range entriesToAppend {
		//	snapshotEntriesBatch = append(snapshotEntriesBatch, entry)
		//}

		// If we filled the chunk for main db records, we will return so that there is no
		// gap between the most recently added DBEntry and the next ancestral record. Otherwise,
		// we will keep going with the loop and add all the ancestral records.
		if mainDbFilled && indexChunk == len(mainDbBatchEntries) {
			break
		}
		if snap.CheckAnceststralRecordExistenceByte(ancestralEntry.Value) {
			snapshotEntriesBatch = append(snapshotEntriesBatch, dbEntry)
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

	// If no records are present in the db for the provided prefix and startKey, return an empty db entry.
	if len(snapshotEntriesBatch) == 0 {
		if ancestralDbFilled {
			// This can happen in a rare case where all ancestral records were non-existent records and
			// no record from the main DB was added.
			lastAncestralEntry := ancestralDbBatchEntries[len(ancestralDbBatchEntries)-1]
			dbEntry := snap.AncestralRecordToDBEntry(lastAncestralEntry)
			return snap.GetSnapshotChunk(mainDb, prefix, dbEntry.Key)
		} else {
			snapshotEntriesBatch = append(snapshotEntriesBatch, EmptyDBEntry())
			return snapshotEntriesBatch, false, false, nil
		}
	}

	// Check if the semaphores have changed as we were fetching the snapshot chunk. It could happen
	// that a flush was taking place right when we were reading records from the database. To detect
	// such edge-case, we compare the current semaphore counters with the ones we've copied when
	// we started retrieving the database chunk.
	snap.SemaphoreLock.Lock()
	ancestralDBSemaphoreAfter := snap.AncestralDBSemaphore
	mainDBSemaphoreAfter := snap.MainDBSemaphore
	snap.SemaphoreLock.Unlock()
	if ancestralDBSemaphoreBefore != ancestralDBSemaphoreAfter ||
		mainDBSemaphoreBefore != mainDBSemaphoreAfter {
		return nil, false, true, nil
	}

	// If either of the chunks is full, we should return true.
	return snapshotEntriesBatch, mainDbFilled || ancestralDbFilled, false, nil
}

// SetSnapshotChunk is called to put the snapshot chunk that we've got from a peer in the database.
func (snap *Snapshot) SetSnapshotChunk(mainDb *badger.DB, chunk []*DBEntry) error {
	var err error
	var syncGroup sync.WaitGroup

	snap.timer.Start("SetSnapshotChunk.Total")
	// We use badgerDb write batches as it's the fastest way to write multiple records to the db.
	wb := mainDb.NewWriteBatch()
	defer wb.Cancel()

	// Setup two go routines to do the db write and the checksum computation in parallel.
	syncGroup.Add(2)
	go func() {
		defer syncGroup.Done()
		//snap.timer.Start("SetSnapshotChunk.Set")

		for _, dbEntry := range chunk {
			localErr := wb.Set(dbEntry.Key, dbEntry.Value) // Will create txns as needed.
			if localErr != nil {
				glog.Errorf("Snapshot.SetSnapshotChunk: Problem setting db entry in write batch")
				err = localErr
				return
			}
		}
		if localErr := wb.Flush(); localErr != nil {
			glog.Errorf("Snapshot.SetSnapshotChunk: Problem flushing write batch to db")
			err = localErr
			return
		}
		//snap.timer.End("SetSnapshotChunk.Set")
	}()
	go func() {
		defer syncGroup.Done()

		//snap.timer.Start("SetSnapshotChunk.Checksum")
		for _, dbEntry := range chunk {
			if localErr := snap.Checksum.AddBytes(EncodeKeyValue(dbEntry.Key, dbEntry.Value)); localErr != nil {
				glog.Errorf("Snapshot.SetSnapshotChunk: Problem adding checksum")
				err = localErr
				return
			}
		}
		if localErr := snap.Checksum.Wait(); localErr != nil {
			err = localErr
			glog.Errorf("Snapshot.SetSnapshotChunk: Problem waiting for the checksum")
		}

		//snap.timer.End("SetSnapshotChunk.Checksum")
	}()

	syncGroup.Wait()
	if err != nil {
		return err
	}

	snap.timer.End("SetSnapshotChunk.Total")

	snap.timer.Print("SetSnapshotChunk.Total")
	snap.timer.Print("SetSnapshotChunk.Set")
	snap.timer.Print("SetSnapshotChunk.Checksum")
	return nil
}

// -------------------------------------------------------------------------------------
// Timer
// -------------------------------------------------------------------------------------

// Timer is used for convenience to time certain events during development.
type Timer struct {
	totalElapsedTimes map[string]float64
	lastTimes         map[string]time.Time
	mode              bool
}

func (t *Timer) Initialize() {
	t.totalElapsedTimes = make(map[string]float64)
	t.lastTimes = make(map[string]time.Time)
	// Comment this to stop timing
	t.mode = EnableTimer
}

func (t *Timer) Start(eventName string) {
	if t.mode != EnableTimer {
		return
	}
	if _, exists := t.lastTimes[eventName]; !exists {
		t.totalElapsedTimes[eventName] = 0.0
	}
	t.lastTimes[eventName] = time.Now()
}

func (t *Timer) End(eventName string) {
	if t.mode != EnableTimer {
		return
	}
	if _, exists := t.totalElapsedTimes[eventName]; !exists {
		glog.Errorf("Timer.End: Error called with non-existent eventName")
		return
	}
	t.totalElapsedTimes[eventName] += time.Since(t.lastTimes[eventName]).Seconds()
}

func (t *Timer) Print(eventName string) {
	if t.mode != EnableTimer {
		return
	}
	if _, exists := t.lastTimes[eventName]; exists {
		glog.Infof("Timer.End: event (%s) total elapsed time (%v)",
			eventName, t.totalElapsedTimes[eventName])
	}
}
