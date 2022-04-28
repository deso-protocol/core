package lib

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/circl/group"
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/go-deadlock"
	"github.com/dgraph-io/badger/v3"
	"github.com/fatih/color"
	"github.com/golang/glog"
	"github.com/oleiade/lane"
	"github.com/pkg/errors"
	"golang.org/x/sync/semaphore"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"time"
)

var (
	// Prefix to store ancestral records. Ancestral records represent historical values of main db entries that were
	// modified during a snapshot epoch. For instance if we modified some record <key, value> -> <key, value_new> in
	// the main db, we will store <key, value> in the ancestral records under:
	//  <prefix [1]byte, blockheight [8]byte, key []byte> -> <value []byte, existence_byte [1]byte>
	// The existence_byte is either 0 or 1 depending on whether <key, value> previously existed in the main db. The
	// existence_byte allows us to quickly determine if a given record existed in a snapshot without making additional
	// lookups. It is part of the value, instead of the key, so that we can confirm that a given key has already been saved
	// to the ancestral records by performing just a single lookup. If it was part of the key, we would have needed two.
	_prefixAncestralRecord = []byte{0}

	// Last Snapshot epoch metadata prefix is used to encode information about the last snapshot epoch.
	// This includes the SnapshotBlockHeight, CurrentEpochChecksumBytes, CurrentEpochBlockHash.
	// 	<prefix [1]byte> -> <SnapshotEpochMetadata>
	_prefixLastEpochMetadata = []byte{1}

	// This prefix saves the checksum bytes after a flush.
	// 	<prefix [1]byte> -> <checksum bytes [33]byte>
	_prefixSnapshotChecksum = []byte{2}

	// This prefix saves the snapshot status that is saved periodically to ensure node can recover after sudden crash.
	// 	<prefix [1]byte> -> <snapshot status bytes [20]byte>
	_prefixSnapshotStatus = []byte{3}

	// This prefix saves the status of the operation channel so we know if the node shut down properly last time.
	_prefixOperationChannelStatus = []byte{4}

	_prefixMigrationStatus = []byte{5}
)

// -------------------------------------------------------------------------------------
// Snapshot
// -------------------------------------------------------------------------------------

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
	SnapshotDb      *badger.DB
	SnapshotDbMutex *sync.Mutex
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
	OperationChannel *SnapshotOperationChannel

	// Checksum allows us to confirm integrity of the state so that when we're syncing with peers,
	// we are confident that data wasn't tampered with.
	Checksum *StateChecksum

	Migrations *EncoderMigration

	// CurrentEpochSnapshotMetadata is the information about the currently stored complete snapshot, which
	// reflects the state of the blockchain at the largest height divisible by SnapshotBlockHeightPeriod.
	// The metadata includes the block height and its block hash of when the snapshot was taken, and the
	// state checksum.
	CurrentEpochSnapshotMetadata *SnapshotEpochMetadata

	// Status is used to monitor the health of the snapshot. Snapshot is updated concurrently to the main
	// block processing thread. Snapshot is efficient and doesn't stall the main thread, instead it does
	// the snapshot computation in parallel. In a way, Snapshot plays catch with the main thread. As you
	// can imagine this means a lot of concurrency control. Status contains information about the current
	// progress of the main and snapshot threads. We use it to recover the Snapshot in case node was shut
	// down incorrectly.
	Status *SnapshotStatus

	mainDb *badger.DB
	params *DeSoParams

	isTxIndex       bool
	disableChecksum bool

	// ExitChannel is used to stop the snapshot when shutting down the node.
	ExitChannel chan bool
	// updateWaitGroup is used to wait for snapshot loop to finish.
	updateWaitGroup sync.WaitGroup
	stopped         bool

	timer *Timer
}

// NewSnapshot creates a new snapshot instance.
func NewSnapshot(mainDb *badger.DB, mainDbDirectory string, snapshotBlockHeightPeriod uint64, isTxIndex bool,
	disableChecksum bool, params *DeSoParams, disableMigrations bool) (_snap *Snapshot, _err error, _shouldRestart bool) {

	// Initialize the ancestral records database
	snapshotDirectory := filepath.Join(GetBadgerDbPath(mainDbDirectory), "snapshot")
	snapshotOpts := PerformanceBadgerOptions(snapshotDirectory)
	snapshotOpts.ValueDir = GetBadgerDbPath(snapshotDirectory)
	snapshotDb, err := badger.Open(snapshotOpts)
	if err != nil {
		return nil, errors.Wrapf(err, "NewSnapshot: Problem creating SnapshotDb"), true
	}
	glog.Infof("Snapshot BadgerDB Dir: %v", snapshotOpts.Dir)
	glog.Infof("Snapshot BadgerDB ValueDir: %v", snapshotOpts.ValueDir)
	if snapshotBlockHeightPeriod == 0 {
		snapshotBlockHeightPeriod = SnapshotBlockHeightPeriod
	}
	var snapshotDbMutex sync.Mutex

	// Retrieve and initialize the checksum.
	checksum := &StateChecksum{}
	if err := checksum.Initialize(snapshotDb, &snapshotDbMutex); err != nil {
		return nil, errors.Wrapf(err, "NewSnapshot: Problem reading Checksum"), true
	}

	// Retrieve the snapshot epoch metadata from the snapshot db.
	metadata := &SnapshotEpochMetadata{}
	if err := metadata.Initialize(snapshotDb, &snapshotDbMutex); err != nil {
		return nil, errors.Wrapf(err, "NewSnapshot: Problem reading SnapshotEpochMetadata"), true
	}

	operationChannel := &SnapshotOperationChannel{}
	if err := operationChannel.Initialize(snapshotDb, &snapshotDbMutex); err != nil {
		return nil, errors.Wrapf(err, "NewSnapshot: Problem reading SnapshotOperationChannel"), true
	}

	// Retrieve and initialize the snapshot status.
	status := &SnapshotStatus{}
	if err := status.Initialize(snapshotDb, &snapshotDbMutex); err != nil {
		return nil, errors.Wrapf(err, "NewSnapshot: Problem reading SnapshotStatus"), true
	}

	// Retrieve and initialize snapshot migrations.
	migrations := &EncoderMigration{}
	if err := migrations.Initialize(
		mainDb, snapshotDb, &snapshotDbMutex, status.CurrentBlockHeight, params, disableMigrations); err != nil {
		return nil, errors.Wrapf(err, "NewSnapshot: Problem reading EncoderMigration"), true
	}

	// If this condition is true, the snapshot is broken and we need to start the recovery process.
	// We will revert the blockchain to the last snapshot epoch and restart the node. After the restart,
	// the node will rebuild snapshot by resyncing blocks up to the tip, starting from last snapshot epoch.
	shouldRestart := false
	if operationChannel.StateSemaphore > 0 || status.IsFlushing() {
		glog.Errorf(CLog(Red, fmt.Sprintf("NewSnapshot: Node didn't shut down properly last time. Entering a "+
			"recovery mode. The node will roll back to last snapshot epoch block height (%v) and hash (%v), then restart.",
			metadata.SnapshotBlockHeight, metadata.CurrentEpochBlockHash)))
		shouldRestart = true
	}

	if !shouldRestart {
		if err := migrations.StartMigrations(); err != nil {
			glog.Errorf(CLog(Red, fmt.Sprintf("NewSnapshot: Migration failed: Error (%v)", err)))
			shouldRestart = true
		}
	}

	// Initialize the timer.
	timer := &Timer{}
	timer.Initialize()

	// Set the snapshot.
	snap := &Snapshot{
		SnapshotDb:                   snapshotDb,
		SnapshotDbMutex:              &snapshotDbMutex,
		DatabaseCache:                lru.NewKVCache(DatabaseCacheSize),
		AncestralFlushCounter:        uint64(0),
		SnapshotBlockHeightPeriod:    snapshotBlockHeightPeriod,
		OperationChannel:             operationChannel,
		Checksum:                     checksum,
		Migrations:                   migrations,
		CurrentEpochSnapshotMetadata: metadata,
		AncestralMemory:              lane.NewDeque(),
		Status:                       status,
		params:                       params,
		isTxIndex:                    isTxIndex,
		disableChecksum:              disableChecksum,
		timer:                        timer,
		ExitChannel:                  make(chan bool),
	}
	// Run the snapshot main loop.
	go snap.Run()

	return snap, nil, shouldRestart
}

// Run is the snapshot main loop. It handles the operations from the OperationChannel.
func (snap *Snapshot) Run() {
	glog.V(1).Infof("Snapshot.Run: Starting update thread")

	snap.updateWaitGroup.Add(1)
	for {
		operation := snap.OperationChannel.DequeueOperationStateless()
		switch operation.operationType {
		case SnapshotOperationFlush:
			glog.V(2).Infof("Snapshot.Run: Flushing ancestral records with counter")
			snap.FlushAncestralRecords()

		case SnapshotOperationProcessBlock:
			glog.V(2).Infof("Snapshot.Run: Getting into the process block with height (%v)",
				operation.blockNode.Height)
			snap.SnapshotProcessBlock(operation.blockNode)

		case SnapshotOperationProcessChunk:
			glog.V(1).Infof("Snapshot.Run: Number of operations in the operation channel (%v)",
				snap.OperationChannel.GetStatus())
			if err := snap.SetSnapshotChunk(operation.mainDb, operation.mainDbMutex, operation.snapshotChunk,
				operation.blockHeight); err != nil {
				glog.Errorf("Snapshot.Run: Problem adding snapshot chunk to the db")
			}

		case SnapshotOperationChecksumAdd:
			if err := snap.Checksum.AddOrRemoveBytesWithMigrations(operation.checksumKey, operation.checksumValue,
				snap.Status.CurrentBlockHeight, snap.Migrations.migrationChecksums, true); err != nil {
				glog.Errorf("Snapshot.Run: Problem adding checksum bytes operation (%v)", operation)
			}

		case SnapshotOperationChecksumRemove:
			if err := snap.Checksum.AddOrRemoveBytesWithMigrations(operation.checksumKey, operation.checksumValue,
				snap.Status.CurrentBlockHeight, snap.Migrations.migrationChecksums, false); err != nil {
				glog.Errorf("Snapshot.Run: Problem removing checksum bytes operation (%v)", operation)
			}

		case SnapshotOperationChecksumPrint:
			stateChecksum, err := snap.Checksum.ToBytes()
			if err != nil {
				glog.Errorf("Snapshot.Run: Problem getting checksum bytes (%v)", err)
			}
			glog.V(2).Infof("Snapshot.Run: PrintText (%s) Current checksum (%v)", operation.printText, stateChecksum)

		case SnapshotOperationExit:
			glog.V(2).Infof("Snapshot.Run: Exiting the operation loop")
			if err := snap.Checksum.Wait(); err != nil {
				glog.Errorf("Snapshot.Run: Problem waiting for the checksum, error (%v)", err)
			}
			snap.OperationChannel.FinishOperation()
			snap.updateWaitGroup.Done()
			return
		}
		snap.OperationChannel.FinishOperation()
	}
}

func (snap *Snapshot) Stop() {
	glog.Infof("Snapshot.Stop: Stopping the run loop")
	if snap.stopped {
		return
	}
	snap.stopped = true

	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationExit,
	})
	snap.WaitForAllOperationsToFinish()
	snap.updateWaitGroup.Wait()

	// This method doesn't close the snapshot db, make sure to call in the parent context:
	// 	snap.SnapshotDb.Close()
	// It's important!!!
}

// ForceResetToLastSnapshot is a doomsday scenario recovery mode. It will be triggered if the node was shutdown midway,
// resulting in a corrupted ancestral records or checksum. To recover from this situation, we will revert to the beginning
// of the current snapshot epoch. We do this by disconnecting blocks from the tip to the epoch's start and resetting the checksum.
func (snap *Snapshot) ForceResetToLastSnapshot(chain *Blockchain) error {
	snap.stopped = true

	// First we'll stop and reset the snapshot operation channel.
	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationExit,
	})
	snap.WaitForAllOperationsToFinish()
	snap.updateWaitGroup.Wait()
	snap.OperationChannel.StateSemaphore = 0

	// Now, we'll reset the snapshot db status semaphores.
	snap.Status.MainDBSemaphore = 0
	snap.Status.AncestralDBSemaphore = 0

	// Now, disconnect the blocks to the beginning of the snapshot epoch, or equivalently, end of the last snapshot epoch.
	lastEpochHeight := snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight
	err := chain.DisconnectBlocksToHeight(lastEpochHeight)
	if err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem disconnecting blocks")
	}

	// Reset the state checksum to the one we got at the beginning of this epoch.
	if len(snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes) == 0 {
		snap.Checksum.ResetChecksum()
	} else {
		err = snap.Checksum.FromBytes(snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes)
		if err != nil {
			return errors.Wrapf(err, "ForceResetToLastSnapshot: problem resetting checksum bytes")
		}
	}
	err = snap.Checksum.SaveChecksum()
	if err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem saving checksum")
	}

	// Similarly, we'll reset the encoder migration checksums.
	snap.Migrations.ResetChecksums()
	if err = snap.Migrations.SaveMigrations(); err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem saving migrations")
	}

	// Save the operation channel status and the db status.
	if err = snap.OperationChannel.SaveOperationChannel(); err != nil {
		return errors.Errorf("ForceResetToLastSnapshot: Problem saving operation channel in database. Error: (%v)", err)
	}
	snap.Status.SaveStatus()

	// Delete all ancestral records for the current snapshot epoch.
	if err = snap.DeleteAncestralRecords(lastEpochHeight); err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem deleting ancestral records at height (%v)", lastEpochHeight)
	}

	// Now we'll verify that the final state checksum matches the last snapshot checksum. We do it in a slightly hacky way
	// where we create and start an empty migration. The StartMigration function will basically scan the entire node's
	// db and compute the checksum. It's easier than having a separate function for this; although, we might have a
	// dedicated function for this in the future for better code clarity.
	glog.Infof(CLog(Yellow, "ForceResetToLastSnapshot: Finished node reset, will now proceed to verify state checksum."))
	verificationMigration := EncoderMigration{}
	verificationMigration.InitializeSingleHeight(chain.db, snap.SnapshotDb, snap.SnapshotDbMutex, lastEpochHeight, snap.params)
	if err := verificationMigration.StartMigrations(); err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem starting verification migration.")
	}
	if len(verificationMigration.migrationChecksums) != 1 {
		return errors.Errorf("ForceResetToLastSnapshot: Number of migration checksums is invalid.")
	}
	verificationChecksum, err := verificationMigration.migrationChecksums[0].Checksum.ToBytes()
	if err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem getting verification migration.")
	}
	if len(snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes) == 0 {
		identitySum := &StateChecksum{}
		identitySum.Initialize(nil, nil)
		snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes, err = identitySum.ToBytes()
		if err != nil {
			return errors.Wrapf(err, "ForceResetToLastSnapshot: Current epoch checksum was empty but failed to reset")
		}
	}
	// Make sure the snapshot epoch checksum is equal to the checksum that we've computed during the StartMigrations,
	// i.e. the checksum we got by scanning the entire db and manually recomputing the checksum from scratch.
	// This check is very important, if it fails then it means that there is no way for us to recover and we should resync.
	if !reflect.DeepEqual(snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes, verificationChecksum) {

		return errors.Errorf("ForceRestartToLastSnapshot: Snapshot epoch checksum: (%v), and verification "+
			"checksum: (%v), are not equal. This means recovery failed. Unfortunatelly, we have to resync your node.",
			snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes, verificationChecksum)
	}

	if err := snap.SnapshotDb.Close(); err != nil {
		return errors.Wrapf(err, "ForceResetToLastSnapshot: Problem closing snapshot db.")
	}
	glog.Infof(CLog(Yellow, "ForceResetToLastSnapshot: Finished rolling back blocks and recovering snapshot. Node should now be restarted."))
	return nil
}

// StartAncestralRecordsFlush updates the ancestral records after a UtxoView flush. This function should be called in a
// after all UtxoView flushes. shouldIncrement is usually set to true and indicates that we are supposed to update the
// db semaphores. The semaphore are used to manage concurrency between the main and ancestral dbs.
func (snap *Snapshot) StartAncestralRecordsFlush(shouldIncrement bool) {
	// If snapshot is broken then there's nothing to do.
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Initiated the flush, shouldIncrement: (%v)", shouldIncrement)

	// Signal that the main db update has finished by incrementing the main semaphore.
	// Also signal that the ancestral db write started by increasing the ancestral semaphore.
	if shouldIncrement {
		snap.Status.MemoryLock.Lock()
		snap.Status.IncrementMainDbSemaphoreMemoryLockRequired()
		snap.Status.IncrementAncestralDBSemaphoreMemoryLockRequired()
		snap.Status.MemoryLock.Unlock()
	}
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Sending counter (%v) to the CounterChannel", snap.AncestralFlushCounter)
	// We send the flush counter to the counter to indicate that a flush should take place.
	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationFlush,
	})
}

func (snap *Snapshot) PrintChecksum(text string) {
	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationChecksumPrint,
		printText:     text,
	})
}

func (snap *Snapshot) FinishProcessBlock(blockNode *BlockNode) {
	glog.V(1).Infof("Snapshot.FinishProcessBlock: Processing block with height (%v) and hash (%v)",
		blockNode.Height, blockNode.Hash)

	snap.CurrentEpochSnapshotMetadata.updateMutex.Lock()
	defer snap.CurrentEpochSnapshotMetadata.updateMutex.Unlock()
	if uint64(blockNode.Height)%snap.SnapshotBlockHeightPeriod == 0 &&
		uint64(blockNode.Height) > snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight {

		snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight = uint64(blockNode.Height)
		snap.CurrentEpochSnapshotMetadata.CurrentEpochBlockHash = blockNode.Hash
	}

	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationProcessBlock,
		blockNode:     blockNode,
	})
}

func (snap *Snapshot) ProcessSnapshotChunk(mainDb *badger.DB, mainDbMutex *deadlock.RWMutex,
	snapshotChunk []*DBEntry, blockHeight uint64) {
	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationProcessChunk,
		mainDb:        mainDb,
		mainDbMutex:   mainDbMutex,
		snapshotChunk: snapshotChunk,
		blockHeight:   blockHeight,
	})
}

func (snap *Snapshot) AddChecksumBytes(key []byte, value []byte) {
	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationChecksumAdd,
		checksumKey:   key,
		checksumValue: value,
	})
}

func (snap *Snapshot) RemoveChecksumBytes(key []byte, value []byte) {
	snap.OperationChannel.EnqueueOperation(&SnapshotOperation{
		operationType: SnapshotOperationChecksumRemove,
		checksumKey:   key,
		checksumValue: value,
	})
}

// WaitForAllOperationsToFinish will busy-wait for the snapshot channel to process all
// current operations. Spinlocks are undesired but it's the easiest solution in this case,
func (snap *Snapshot) WaitForAllOperationsToFinish() {
	// Define some helper variables so that the node prints nice logs.
	initialLen := int(snap.OperationChannel.GetStatus())
	printMap := make(map[int]bool)
	for ii := 0; ii <= 9; ii++ {
		printMap[ii] = false
	}
	printProgress := func(currentLen int32) {
		var div int
		if initialLen > 0 && int(currentLen) < initialLen {
			div = 9 - (10*int(currentLen))/initialLen
		} else {
			div = 0
		}
		if !printMap[div] {
			progress := ""
			for ii := 0; ii <= 9; ii++ {
				if ii <= div {
					progress += "█"
				} else {
					progress += "▒"
				}
			}
			glog.Infof(CLog(Magenta, fmt.Sprintf("Finishing snapshot operations, left: (%v), progress: %v",
				int(currentLen), progress)))
			printMap[div] = true
		}
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	for {
		<-ticker.C

		operationChannelStatus := snap.OperationChannel.GetStatus()
		if operationChannelStatus == 0 {
			break
		}
		printProgress(operationChannelStatus)
	}
}

// PrepareAncestralRecordsFlush adds a new instance of ancestral cache to the AncestralMemory deque.
// It must be called prior to calling StartAncestralRecordsFlush.
func (snap *Snapshot) PrepareAncestralRecordsFlush() {
	// Signal that the main db update has started by holding the MemoryLock and incrementing the MainDBSemaphore.
	snap.Status.MemoryLock.Lock()
	// If at this point we're flushing to the main DB, i.e. the MainDBSemaphore is odd, then it means we're nesting
	// calls to PrepareAncestralRecordsFlush()
	if snap.Status.IsFlushingToMainDBMemoryLockRequired() {
		glog.Fatalf("Nested calls to PrepareAncestralRecordsFlush() " +
			"detected. Make sure you call StartAncestralRecordsFlush before " +
			"calling PrepareAncestralRecordsFlush() again")
	}
	snap.Status.IncrementMainDbSemaphoreMemoryLockRequired()
	snap.Status.MemoryLock.Unlock()

	// Add an entry to the ancestral memory.
	snap.AncestralFlushCounter += 1
	index := snap.AncestralFlushCounter
	blockHeight := snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight
	snap.AncestralMemory.Append(NewAncestralCache(index, blockHeight))
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
	latestAncestralCache := snap.AncestralMemory.Last().(*AncestralCache)
	if latestAncestralCache.id != index {
		return fmt.Errorf("Snapshot.PrepareAncestralRecords: last ancestral cache index (%v) is "+
			"greater than current flush index (%v)", latestAncestralCache.id, index)
	}

	// If the record already exists in the ancestral cache, skip.
	if _, ok := latestAncestralCache.AncestralRecordsMap[key]; ok {
		return nil
	}

	// Add the record to the records key list and the adequate records list.
	latestAncestralCache.AncestralRecordsMap[key] = &AncestralRecordValue{
		Value:   value,
		Existed: existed,
	}
	return nil
}

// FlushAncestralRecords updates the ancestral records after a UtxoView flush.
// This function should be called in a go-routine after all UtxoView flushes.
func (snap *Snapshot) FlushAncestralRecords() {
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Initiated the flush")

	// Make sure we've finished all checksum computation before we proceed with the flush.
	// Since this gets called after all snapshot operations are enqueued after the main db
	// flush, the order of operations is preserved; however, there could still be some
	// snapshot worker threads running so we want to wait until they're done.
	err := snap.Checksum.Wait()
	if err != nil {
		glog.Errorf("Snapshot.StartAncestralRecordsFlush: Error while waiting "+
			"for checksum: (%v)", err)
		snap.StartAncestralRecordsFlush(false)
		return
	}

	// Pull items off of the deque for writing. We say "last" as in oldest, i.e. the first element of AncestralMemory.
	oldestAncestralCache := snap.AncestralMemory.First().(*AncestralCache)

	blockHeight := oldestAncestralCache.blockHeight
	if blockHeight != snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight {
		glog.Infof("Snapshot.StartAncestralRecordsFlush: AncestralMemory blockHeight (%v) doesn't match current "+
			"metadata blockHeight (%v), number of operations in operationChannel (%v)", blockHeight,
			snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight, len(snap.OperationChannel.OperationChannel))
		// Signal that the ancestral db write has finished by incrementing the semaphore.
		snap.Status.MemoryLock.Lock()
		snap.Status.IncrementAncestralDBSemaphoreMemoryLockRequired()
		snap.Status.MemoryLock.Unlock()

		snap.AncestralMemory.Shift()
		return
	}
	// First sort the keys so that we write to BadgerDB in order.
	recordsKeyList := make([]string, 0, len(oldestAncestralCache.AncestralRecordsMap))
	for kk := range oldestAncestralCache.AncestralRecordsMap {
		recordsKeyList = append(recordsKeyList, kk)
	}
	sort.Strings(recordsKeyList)
	glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Finished sorting map keys")

	// We launch a new read-write transaction to set the records.
	snap.SnapshotDbMutex.Lock()
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
		glog.V(2).Infof("Snapshot.StartAncestralRecordsFlush: Adding (%v) ancestral records", len(oldestAncestralCache.AncestralRecordsMap))
		for _, key := range recordsKeyList {
			// We store keys as strings because they're easier to store and sort this way.
			keyBytes, err := hex.DecodeString(key)
			if err != nil {
				return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem "+
					"decoding copyMapKeyList key: %v", key)
			}

			// We check whether this record is already present in ancestral records,
			// if so then there's nothing to do. What we want is err == badger.ErrKeyNotFound
			_, err = snap.GetAncestralRecordsKeyWithTxn(txn, keyBytes, blockHeight)
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
			value, exists := oldestAncestralCache.AncestralRecordsMap[key]
			if !exists {
				return fmt.Errorf("Snapshot.StartAncestralRecordsFlush: Error, key is not " +
					"in AncestralRecordsMap. This should never happen")
			}
			err = snap.DBSetAncestralRecordWithTxn(txn, blockHeight, keyBytes, value)
			if err != nil {
				return errors.Wrapf(err, "Snapshot.StartAncestralRecordsFlush: Problem "+
					"flushing a record from copyAncestralMap at key %v:", key)
			}
		}
		return nil
	})
	snap.SnapshotDbMutex.Unlock()
	if err != nil {
		// If any error occurred, then we should redo this memory write. During the restart, we will re-write all
		// entries. If the error happened during a partial write, e.g. we didn't write all records in recordsKeyList,
		// we'll redo them in the next write of this ancestralCache. The only scenario where that wouldn't happen
		// is if the node stopped suddenly. We can detect that via comparing semaphore counters on boot.
		glog.Errorf("Snapshot.StartAncestralRecordsFlush: Problem flushing snapshot, error %v", err)
		snap.StartAncestralRecordsFlush(false)
		return
	}

	// Signal that the ancestral db write has finished by incrementing the semaphore.
	snap.Status.MemoryLock.Lock()
	snap.Status.IncrementAncestralDBSemaphoreMemoryLockRequired()
	snap.Status.MemoryLock.Unlock()

	snap.AncestralMemory.Shift()
}

// DeleteAncestralRecords is used to delete ancestral records for the provided height.
func (snap *Snapshot) DeleteAncestralRecords(height uint64) error {
	glog.V(2).Infof("Snapshot.DeleteAncestralRecords: Deleting snapshotDb for height (%v)", height)

	snap.timer.Start("Snapshot.DeleteAncestralRecords")
	var prefix []byte
	prefix = append(prefix, _prefixAncestralRecord...)
	prefix = append(prefix, EncodeUint64(height)...)

	snap.SnapshotDbMutex.Lock()
	defer snap.SnapshotDbMutex.Unlock()

	var keys [][]byte
	err := snap.SnapshotDb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.AllVersions = false
		opts.PrefetchValues = false
		// Iterate over the prefix as long as there are valid keys in the DB.
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := it.Item().KeyCopy(nil)
			keys = append(keys, key)
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "DeleteAncestralRecords: Problem iterating through the height")
	}
	err = snap.SnapshotDb.Update(func(txn *badger.Txn) error {
		for _, key := range keys {
			err := txn.Delete(key)
			if err != nil {
				return errors.Wrapf(err, "DeleteAncestralRecords: Problem deleting key (%v)", key)
			}
		}
		return nil
	})
	if err != nil {
		return errors.Wrapf(err, "DeleteAncestralRecords: Problem deleting the entries")
	}
	snap.timer.End("Snapshot.DeleteAncestralRecords")
	snap.timer.Print("Snapshot.DeleteAncestralRecords")
	return nil
}

// GetAncestralRecordsKey is used to get an ancestral record key from a main DB key.
// 	<prefix [1]byte, block height [8]byte, key []byte> -> <value []byte, existence_byte [1]byte>
func (snap *Snapshot) GetAncestralRecordsKey(key []byte, blockHeight uint64) []byte {
	var prefix []byte

	// Append the ancestral records prefix.
	prefix = append(prefix, _prefixAncestralRecord...)

	// Append block height, which is the current snapshot identifier.
	prefix = append(prefix, EncodeUint64(blockHeight)...)

	// Finally, append the main DB key.
	prefix = append(prefix, key...)
	return prefix
}

// GetAncestralRecordsKey is warpper around an ancestral record.
func (snap *Snapshot) GetAncestralRecordsKeyWithTxn(txn *badger.Txn, key []byte, blockHeight uint64) (
	_record *badger.Item, _err error) {

	recordsKey := snap.GetAncestralRecordsKey(key, blockHeight)
	return txn.Get(recordsKey)
}

// DBSetAncestralRecordWithTxn sets a record corresponding to our ExistingRecordsMap.
// We append a []byte{1} to the end to indicate that this is an existing record, and
// we append a []byte{0} to the end to indicate that this is a NON-existing record. We
// need to create this distinction to tell the difference between a record that was
// updated to have an *empty* value vs a record that was deleted entirely.
func (snap *Snapshot) DBSetAncestralRecordWithTxn(
	txn *badger.Txn, blockHeight uint64, keyBytes []byte, value *AncestralRecordValue) error {

	if value.Existed {
		return txn.Set(snap.GetAncestralRecordsKey(keyBytes, blockHeight), append(value.Value, byte(1)))
	} else {
		return txn.Set(snap.GetAncestralRecordsKey(keyBytes, blockHeight), []byte{byte(0)})
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
	if height > snap.Status.CurrentBlockHeight {
		snap.Status.CurrentBlockHeight = height
		// Check if we've reached a migration blockheight and so should upgrade the checksum.
		if migrationChecksum := snap.Migrations.GetMigrationChecksumAtBlockheight(height); migrationChecksum != nil {
			for ii := 0; ii < MetadataRetryCount; ii++ {
				checksumBytes, err := migrationChecksum.ToBytes()
				if err != nil {
					glog.Errorf("Snapshot.SnapshotProcessBlock: Problem getting checksum migration "+
						"bytes: Error (%v)", err)
					continue
				}
				if err := snap.Checksum.FromBytes(checksumBytes); err != nil {
					glog.Errorf("Snapshot.SnapshotProcessBlock: Problem calling FromBytes on checksum "+
						"migration: Error (%v)", err)
					continue
				}
				// Remove the migrations, we won't need it anymore.
				snap.Migrations.CleanupMigrations(height)
				break
			}
		}
	}

	snap.CurrentEpochSnapshotMetadata.updateMutex.Lock()
	defer snap.CurrentEpochSnapshotMetadata.updateMutex.Unlock()
	if height == snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight {
		var err error
		// Delete the previous blockHeight, it is not useful anymore.
		//snap.DeleteAncestralRecords(snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight)

		glog.V(1).Infof("Snapshot.SnapshotProcessBlock: About to delete SnapshotBlockHeight (%v) and set new height (%v)",
			snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight, height)

		// Update the snapshot epoch metadata in the snapshot DB.
		for ii := 0; ii < MetadataRetryCount; ii++ {
			snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes, err = snap.Checksum.ToBytes()
			if err != nil {
				glog.Errorf("Snapshot.SnapshotProcessBlock: Problem getting checksum bytes: Error (%v)", err)
				time.Sleep(1 * time.Second)
				continue
			}
			snap.SnapshotDbMutex.Lock()
			err = snap.SnapshotDb.Update(func(txn *badger.Txn) error {
				return txn.Set(_prefixLastEpochMetadata, snap.CurrentEpochSnapshotMetadata.ToBytes())
			})
			snap.SnapshotDbMutex.Unlock()
			if err != nil {
				glog.Errorf("Snapshot.SnapshotProcessBlock: Problem setting snapshot epoch metadata in "+
					"snapshot db: Error (%v)", err)
				if ii == MetadataRetryCount-1 {
					glog.Errorf("Snapshot.SnapshotProcessBlock: Something went wrong, metadata can't be written "+
						"but it should be (%v).\nYou might need to set it manually if you want other nodes to sync from "+
						"you.", snap.CurrentEpochSnapshotMetadata.ToBytes())
				} else {
					// If we encountered an error, sleep one second and retry again.
					time.Sleep(1 * time.Second)
					continue
				}
			}
			break
		}

		glog.V(1).Infof("Snapshot.SnapshotProcessBlock: snapshot checksum is (%v)",
			snap.CurrentEpochSnapshotMetadata.CurrentEpochChecksumBytes)
	}
}

// isState determines if a key is a state-related record.
func (snap *Snapshot) isState(key []byte) bool {
	if !snap.isTxIndex {
		return isStateKey(key)
	} else {
		return isStateKey(key) || isTxIndexKey(key)
	}
}

func (snap *Snapshot) String() string {
	return fmt.Sprintf("< Snapshot | height: %v >",
		snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight)
}

// GetSnapshotChunk fetches a batch of records from the nodes DB that match the provided prefix and
// have a key at least equal to the startKey lexicographically. The function will also fetch ancestral
// records and combine them with the DB records so that the batch reflects an ancestral block.
func (snap *Snapshot) GetSnapshotChunk(mainDb *badger.DB, prefix []byte, startKey []byte) (
	_snapshotEntriesBatch []*DBEntry, _snapshotEntriesFilled bool, _concurrencyFault bool, _err error) {

	// Check if we're flushing to the main db or to the ancestral records. If a flush is currently
	// taking place, we will return a concurrencyFault error because the records are getting modified.
	mainDBSemaphoreBefore, ancestralDBSemaphoreBefore := snap.Status.GetSemaphores()
	if snap.Status.IsFlushing() {
		return nil, false, true, nil
	}

	// This the list of fetched DB entries.
	var snapshotEntriesBatch []*DBEntry
	blockHeight := snap.CurrentEpochSnapshotMetadata.SnapshotBlockHeight

	// Fetch the batch from main DB records with a batch size of about snap.BatchSize.
	mainDbBatchEntries, mainDbFilled, err := DBIteratePrefixKeys(mainDb, prefix, startKey, SnapshotBatchSize)
	if err != nil {
		return nil, false, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}
	// Fetch the batch from the ancestral DB records with a batch size of about snap.BatchSize.
	ancestralDbBatchEntries, ancestralDbFilled, err := DBIteratePrefixKeys(snap.SnapshotDb,
		snap.GetAncestralRecordsKey(prefix, blockHeight), snap.GetAncestralRecordsKey(startKey, blockHeight), SnapshotBatchSize)
	if err != nil {
		return nil, false, false, errors.Wrapf(err, "Snapshot.GetSnapshotChunk: Problem fetching main Db records: ")
	}

	// To combine the main DB entries and the ancestral records DB entries, we iterate through the ancestral records and
	// for each key we add all the main DB keys that are smaller than the currently processed key. The ancestral records
	// entries have priority over the main DB entries, so whenever there are entries with the same key among the two DBs,
	// we will only add the ancestral record entry to our snapshot batch. Also, the loop below might appear like O(n^2)
	// but it's actually O(n) because the inside loop iterates at most O(n) times in total. We call this approach
	// "the caterpillar" and you should know that it sparked some controversy in the dev community. Some think it's
	// unintuitive and error-prone and prefer some suboptimal O(nlogn). Others know that the power of O(n) is immense
	// and worth the tradeoff.

	// Index to keep track of how many main DB entries we've already processed.
	indexChunk := 0
	for _, ancestralEntry := range ancestralDbBatchEntries {
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
	mainDBSemaphoreAfter, ancestralDBSemaphoreAfter := snap.Status.GetSemaphores()
	if ancestralDBSemaphoreBefore != ancestralDBSemaphoreAfter ||
		mainDBSemaphoreBefore != mainDBSemaphoreAfter {
		return nil, false, true, nil
	}

	// If either of the chunks is full, we should return true.
	return snapshotEntriesBatch, mainDbFilled || ancestralDbFilled, false, nil
}

// SetSnapshotChunk is called to put the snapshot chunk that we've got from a peer in the database.
func (snap *Snapshot) SetSnapshotChunk(mainDb *badger.DB, mainDbMutex *deadlock.RWMutex,
	chunk []*DBEntry, blockHeight uint64) error {

	var err error
	var syncGroup sync.WaitGroup

	snap.timer.Start("SetSnapshotChunk.Total")
	// If there's a problem retrieving the snapshot checksum, we'll reschedule this snapshot chunk set.
	initialChecksumBytes, err := snap.Checksum.ToBytes()
	if err != nil {
		glog.Errorf("Snapshot.SetSnapshotChunk: Problem retrieving checksum bytes, error: (%v)", err)
		snap.ProcessSnapshotChunk(mainDb, mainDbMutex, chunk, blockHeight)
		return err
	}

	mainDbMutex.Lock()
	// We use badgerDb write batches as it's the fastest way to write multiple records to the db.
	wb := mainDb.NewWriteBatch()
	defer wb.Cancel()

	// Setup two go routines to do the db write and the checksum computation in parallel.
	syncGroup.Add(2)
	go func() {
		defer syncGroup.Done()
		//snap.timer.Start("SetSnapshotChunk.Set")
		// TODO: Should we split the chunk into batches of 8MB so that we don't write too much data at once?
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
			if localErr := snap.Checksum.AddOrRemoveBytesWithMigrations(dbEntry.Key, dbEntry.Value, blockHeight,
				snap.Migrations.migrationChecksums, true); localErr != nil {
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
	mainDbMutex.Unlock()

	// If there's a problem setting the snapshot checksum, we'll reschedule this snapshot chunk set.
	if err != nil {
		glog.Infof("Snapshot.SetSnapshotChunk: Problem setting the snapshot chunk, error (%v)", err)

		// We reset the snapshot checksum so its initial value, so we won't overlap with processing the next snapshot chunk.
		// If we've errored during a writeBatch set we'll redo this chunk in next SetSnapshotChunk so we're fine with overlaps.
		if err := snap.Checksum.FromBytes(initialChecksumBytes); err != nil {
			panic(fmt.Errorf("Snapshot.SetSnapshotChunk: Problem resetting checksum. This should never happen, "+
				"error: (%v)", err))
		}
		snap.ProcessSnapshotChunk(mainDb, mainDbMutex, chunk, blockHeight)
		return err
	}

	snap.timer.End("SetSnapshotChunk.Total")

	snap.timer.Print("SetSnapshotChunk.Total")
	snap.timer.Print("SetSnapshotChunk.Set")
	snap.timer.Print("SetSnapshotChunk.Checksum")
	return nil
}

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

	snapshotDb      *badger.DB
	snapshotDbMutex *sync.Mutex
}

// Initialize starts the state checksum by initializing it to the identity element.
func (sc *StateChecksum) Initialize(snapshotDb *badger.DB, snapshotDbMutex *sync.Mutex) error {
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

	sc.snapshotDb = snapshotDb
	sc.snapshotDbMutex = snapshotDbMutex

	if snapshotDb == nil || snapshotDbMutex == nil {
		sc.snapshotDbMutex = &sync.Mutex{}
		return nil
	}
	sc.snapshotDbMutex.Lock()
	defer sc.snapshotDbMutex.Unlock()

	// Get snapshot checksum from the db.
	err := sc.snapshotDb.View(func(txn *badger.Txn) error {
		item, err := txn.Get(_prefixSnapshotChecksum)
		if err != nil {
			return err
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		// If we get here, it means we've saved a checksum in the db, so we will set it to the checksum.
		return sc.FromBytes(value)
	})
	if err != nil && err != badger.ErrKeyNotFound {
		return errors.Wrapf(err, "StateChecksum.Initialize: Problem reading checksum from the db")
	}
	return nil
}

func (sc *StateChecksum) SaveChecksum() error {
	sc.snapshotDbMutex.Lock()
	defer sc.snapshotDbMutex.Unlock()

	return sc.snapshotDb.Update(func(txn *badger.Txn) error {
		checksumBytes, err := sc.ToBytes()
		if err != nil {
			return errors.Wrapf(err, "StateChecksum.SaveChecksum: Problem getting checksum bytes")
		}
		return txn.Set(_prefixSnapshotChecksum, checksumBytes)
	})
}

func (sc *StateChecksum) ResetChecksum() {
	sc.checksum = sc.curve.Identity()
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

// AddOrRemoveBytesWithMigrations is used to add or remove (key, value) bytes to the checksum and all encoder migration
// checksums. Depending on the blockHeight, the (key, value) pair might be encoded differently. This is due to encoder
// migrations, which allow for modifications to the encoder schemas that come into effect on pre-defined
// blockHeights. With migrations, nodes won't need to re-sync after a software upgrade. To make migrations work,
// we need a way to maintain a valid checksum across different encoder migration epochs. We do this by keeping a
// checksum copy for each migration epoch and add to it with the respective encoder version. This function is
// called in the context of the snapshot's epoch so that everything happens in sync with the main thread.
// The parameter addBytes determines if we want to add or remove bytes from the checksums.
func (sc *StateChecksum) AddOrRemoveBytesWithMigrations(keyInput []byte, valueInput []byte, blockHeight uint64,
	encoderMigrationChecksums []*EncoderMigrationChecksum, addBytes bool) error {
	key := make([]byte, len(keyInput))
	copy(key, keyInput)
	value := make([]byte, len(valueInput))
	copy(value, valueInput)

	// First check if we can add another worker to the worker pool by trying to increment the semaphore.
	if err := sc.semaphore.Acquire(sc.ctx, 1); err != nil {
		return errors.Wrapf(err, " StateChecksum.AddBytesWithMigrations: problem acquiring semaphore")
	}

	go func() {
		defer sc.semaphore.Release(1)
		// Think about disconnects

		// Sometimes, the entry can be encoded identically across different migrations. Because of that, we will skip
		// the hash_to_curve operation for these bytes to save time. The array encodings keeps a list of all different
		// encodings, and encodingsMapping points migrations to encodings.
		var encodings [][]byte
		var encodingsMapping []int

		// We add the current key, value encoding and encodings for all migrations.
		encodings = append(encodings, EncodeKeyAndValueForChecksum(key, value, blockHeight))
		for _, migration := range encoderMigrationChecksums {
			added := false
			migrationEncoding := EncodeKeyAndValueForChecksum(key, value, migration.BlockHeight)
			for index, encoding := range encodings {
				if reflect.DeepEqual(encoding, migrationEncoding) {
					encodingsMapping = append(encodingsMapping, index)
					added = true
					break
				}
			}
			if !added {
				encodings = append(encodings, migrationEncoding)
				encodingsMapping = append(encodingsMapping, len(encodings)-1)
			}
		}

		// Compute the hash_to_curve for each encoding.
		var hashElements []group.Element
		for _, encoding := range encodings {
			hashElements = append(hashElements, sc.curve.HashToElement(encoding, sc.dst))
		}

		// We will now add or remove bytes based to the checksum and all migrations. Removing means we first negate
		// the curve point.
		if !addBytes {
			for ii, hashElement := range hashElements {
				hashElements[ii] = hashElement.Neg(hashElement)
			}
		}

		// Now add everything.
		sc.AddToChecksum(hashElements[0])
		for ii, index := range encodingsMapping {
			encoderMigrationChecksums[ii].Checksum.AddToChecksum(hashElements[index])
		}
	}()

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

func (sc *StateChecksum) FromBytes(checksumBytes []byte) error {
	// If we get here, it means we've saved a checksum in the db, so we will set it to the checksum.
	if err := sc.semaphore.Acquire(sc.ctx, sc.maxWorkers); err != nil {
		return errors.Wrapf(err, "StateChecksum.Wait: problem acquiring semaphore")
	}
	defer sc.semaphore.Release(sc.maxWorkers)

	err := sc.checksum.UnmarshalBinary(checksumBytes)
	if err != nil {
		return errors.Wrapf(err, "StateChecksum.FromBytes: Problem setting checksum from bytes")
	}
	return nil
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
// SnapshotEpochMetadata
// -------------------------------------------------------------------------------------

type SnapshotEpochMetadata struct {
	// SnapshotBlockHeight is the height of the snapshot.
	SnapshotBlockHeight uint64

	// This is the block height of the very first snapshot this node encountered on its
	// initial hypersync. This field is distinct from SnapshotBlockHeight, which updates
	// every time we enter a new snapshot epoch. It is mainly used by Rosetta to determine
	// where to start returning "real" blocks vs "dummy" blocks. In particular, before the
	// first snapshot, Rosetta will return dummy blocks that don't have any txn operations
	// in them, whereas after the first snapshot, Rosetta will "bootstrap" all the balances
	// in a single mega-block at the snapshot, and then return "real" blocks thereafter.
	FirstSnapshotBlockHeight uint64

	// CurrentEpochChecksumBytes is the bytes of the state checksum for the snapshot at the epoch.
	CurrentEpochChecksumBytes []byte
	// CurrentEpochBlockHash is the hash of the first block of the current epoch. It's used to identify the snapshot.
	CurrentEpochBlockHash *BlockHash

	updateMutex sync.Mutex

	snapshotDb      *badger.DB
	snapshotDbMutex *sync.Mutex
}

func (metadata *SnapshotEpochMetadata) Initialize(snapshotDb *badger.DB, snapshotDbMutex *sync.Mutex) error {
	metadata.SnapshotBlockHeight = uint64(0)
	metadata.FirstSnapshotBlockHeight = uint64(0)
	metadata.CurrentEpochChecksumBytes = []byte{}
	metadata.CurrentEpochBlockHash = NewBlockHash([]byte{})

	metadata.snapshotDb = snapshotDb
	metadata.snapshotDbMutex = snapshotDbMutex

	if snapshotDb == nil || snapshotDbMutex == nil {
		metadata.snapshotDbMutex = &sync.Mutex{}
		return nil
	}
	metadata.snapshotDbMutex.Lock()
	defer metadata.snapshotDbMutex.Unlock()

	err := snapshotDb.View(func(txn *badger.Txn) error {
		// Now get the last epoch metadata.
		item, err := txn.Get(_prefixLastEpochMetadata)
		if err != nil {
			return err
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		rr := bytes.NewReader(value)
		return metadata.FromBytes(rr)
	})
	// If we're starting the hyper sync node for the first time, then there will be no snapshot saved
	// and we'll get ErrKeyNotFound error. That's why we don't error when it happens.
	if err != nil && err != badger.ErrKeyNotFound {
		return errors.Wrapf(err, "Snapshot.NewSnapshot: Problem retrieving snapshot information from db")
	}
	return nil
}

func (metadata *SnapshotEpochMetadata) ToBytes() []byte {
	var data []byte

	data = append(data, UintToBuf(metadata.SnapshotBlockHeight)...)
	data = append(data, UintToBuf(metadata.FirstSnapshotBlockHeight)...)
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

	metadata.FirstSnapshotBlockHeight, err = ReadUvarint(rr)
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

// -------------------------------------------------------------------------------------
// AncestralCache
// -------------------------------------------------------------------------------------

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
	// id is used to identify the AncestralCache.
	id uint64

	blockHeight uint64

	// ExistingRecordsMap keeps track of original main db of records that we modified during
	// UtxoView flush, which is where we're modifying state data. A record for a particular
	// key was either already existing in our state, or not already existing in our state.
	//
	// We store keys as strings because they're easier to store and sort this way.
	AncestralRecordsMap map[string]*AncestralRecordValue
}

func NewAncestralCache(id uint64, blockHeight uint64) *AncestralCache {
	return &AncestralCache{
		id:                  id,
		blockHeight:         blockHeight,
		AncestralRecordsMap: make(map[string]*AncestralRecordValue),
	}
}

// -------------------------------------------------------------------------------------
// SnapshotOperation
// SnapshotOperationChannel
// -------------------------------------------------------------------------------------

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
	mainDb      *badger.DB
	mainDbMutex *deadlock.RWMutex
	// snapshotChunk is the snapshot chunk received from the peer.
	snapshotChunk []*DBEntry
	// snapshot epoch block height.
	blockHeight uint64

	/* SnapshotOperationChecksumAdd, SnapshotOperationChecksumRemove */
	// checksumKey, checksumValue are the bytes we want to add to the state checksum, e.g. when we flush to the db.
	checksumKey   []byte
	checksumValue []byte

	/* SnapshotOperationChecksumPrint */
	// printText is the text we want to put in the print statement.
	printText string
}

type SnapshotOperationChannel struct {
	OperationChannel chan *SnapshotOperation

	StateSemaphore     int32
	StateSemaphoreLock sync.Mutex

	snapshotDb      *badger.DB
	snapshotDbMutex *sync.Mutex
}

func (opChan *SnapshotOperationChannel) Initialize(snapshotDb *badger.DB, snapshotDbMutex *sync.Mutex) error {
	opChan.OperationChannel = make(chan *SnapshotOperation, 100000)
	opChan.StateSemaphore = 0

	opChan.snapshotDb = snapshotDb
	opChan.snapshotDbMutex = snapshotDbMutex

	if snapshotDb == nil || snapshotDbMutex == nil {
		opChan.snapshotDbMutex = &sync.Mutex{}
		return nil
	}
	opChan.snapshotDbMutex.Lock()
	defer opChan.snapshotDbMutex.Unlock()
	err := snapshotDb.View(func(txn *badger.Txn) error {
		item, err := txn.Get(_prefixOperationChannelStatus)
		if err != nil {
			return err
		}
		stateSemaphoreBytes, err := item.ValueCopy(nil)
		if err != nil {
			return errors.Wrapf(err, "problem during ValueCopy")
		}
		rr := bytes.NewReader(stateSemaphoreBytes)
		stateSemaphore, err := ReadUvarint(rr)
		if err != nil {
			return errors.Wrapf(err, "problem during ReadUvarint")
		}
		opChan.StateSemaphore = int32(stateSemaphore)
		return nil
	})
	if err != nil && err != badger.ErrKeyNotFound {
		return errors.Wrapf(err, "SnapshotOperationChannel.Initialize: Problem reading StateSemaphore from db")
	}

	return nil
}

func (opChan *SnapshotOperationChannel) SaveOperationChannel() error {
	opChan.snapshotDbMutex.Lock()
	defer opChan.snapshotDbMutex.Unlock()

	return opChan.snapshotDb.Update(func(txn *badger.Txn) error {
		return txn.Set(_prefixOperationChannelStatus, UintToBuf(uint64(opChan.StateSemaphore)))
	})
}

func (opChan *SnapshotOperationChannel) EnqueueOperation(op *SnapshotOperation) {
	opChan.StateSemaphoreLock.Lock()
	opChan.StateSemaphore += 1
	if opChan.StateSemaphore == 1 {
		if err := opChan.SaveOperationChannel(); err != nil {
			glog.Errorf("SnapshotOperationChannel.EnqueueOperation: Problem saving StateSemaphore to db, error (%v)", err)
		}
	}
	opChan.StateSemaphoreLock.Unlock()

	opChan.OperationChannel <- op
}

func (opChan *SnapshotOperationChannel) DequeueOperationStateless() *SnapshotOperation {
	return <-opChan.OperationChannel
}

func (opChan *SnapshotOperationChannel) FinishOperation() {
	opChan.StateSemaphoreLock.Lock()
	defer opChan.StateSemaphoreLock.Unlock()

	opChan.StateSemaphore -= 1
	if opChan.StateSemaphore == 0 {
		if err := opChan.SaveOperationChannel(); err != nil {
			glog.Errorf("SnapshotOperationChannel.FinishOperation: Problem saving StateSemaphore to db, error (%v)", err)
		}
	}
}

func (opChan *SnapshotOperationChannel) GetStatus() int32 {
	opChan.StateSemaphoreLock.Lock()
	defer opChan.StateSemaphoreLock.Unlock()

	return opChan.StateSemaphore
}

// -------------------------------------------------------------------------------------
// SnapshotStatus
// -------------------------------------------------------------------------------------

type SnapshotStatus struct {
	// MainDBSemaphore and AncestralDBSemaphore are atomically accessed counter semaphores that will be
	// used to control race conditions between main db and ancestral records. They basically manage the concurrency
	// between writes to the main and ancestral dbs.
	MainDBSemaphore      uint64
	AncestralDBSemaphore uint64

	// CurrentBlockHeight is the blockheight of the blockchain tip.
	CurrentBlockHeight uint64
	// MemoryLock is held whenever we modify the MainDBSemaphore or AncestralDBSemaphore.
	MemoryLock sync.Mutex

	// SnapshotStatus is called concurrently by the Server and Snapshot threads. And badger cannot handle
	// concurrent writes to the database. To make sure this concurrency doesn't affect general performance,
	// we use a custom badger.DB to save SnapshotStatus.
	snapshotDb *badger.DB

	// snapshotDbMutex is held whenever we modify snapshotDb.
	snapshotDbMutex *sync.Mutex
}

func (status *SnapshotStatus) Initialize(snapshotDb *badger.DB, snapshotDbMutex *sync.Mutex) error {
	status.MainDBSemaphore = uint64(0)
	status.AncestralDBSemaphore = uint64(0)

	status.snapshotDb = snapshotDb
	status.snapshotDbMutex = snapshotDbMutex

	if snapshotDb == nil || snapshotDbMutex == nil {
		status.snapshotDbMutex = &sync.Mutex{}
		return nil
	}
	if err := status.ReadStatus(); err != nil {
		return errors.Wrapf(err, "SnapshotStatus.ReadStatus: Can't read snapshot status from db")
	}

	return nil
}

func (status *SnapshotStatus) ToBytes() []byte {
	var data []byte
	data = append(data, UintToBuf(status.MainDBSemaphore)...)
	data = append(data, UintToBuf(status.AncestralDBSemaphore)...)
	data = append(data, UintToBuf(status.CurrentBlockHeight)...)

	return data
}

func (status *SnapshotStatus) FromBytes(rr *bytes.Reader) error {
	var err error
	status.MainDBSemaphore, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "SnapshotStatus: Problem reading MainDBSemaphore")
	}

	status.AncestralDBSemaphore, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "SnapshotStatus: Problem reading AncestralDBSemaphore")
	}

	status.CurrentBlockHeight, err = ReadUvarint(rr)
	if err != nil {
		return errors.Wrapf(err, "SnapshotStatus: Problem reading CurrentBlockHeight")
	}
	return nil
}

func (status *SnapshotStatus) SaveStatus() {
	status.snapshotDbMutex.Lock()
	defer status.snapshotDbMutex.Unlock()

	err := status.snapshotDb.Update(func(txn *badger.Txn) error {
		return txn.Set(_prefixSnapshotStatus, status.ToBytes())
	})
	if err != nil {
		glog.Fatalf("SnapshotStatus.SaveStatus: problem writing snapshot status error (%v)", err)
	}
}

func (status *SnapshotStatus) ReadStatus() error {
	status.snapshotDbMutex.Lock()
	defer status.snapshotDbMutex.Unlock()

	err := status.snapshotDb.View(func(txn *badger.Txn) error {
		item, err := txn.Get(_prefixSnapshotStatus)
		if err != nil {
			return err
		}
		statusBytes, err := item.ValueCopy(nil)
		if err != nil {
			return errors.Wrapf(err, "problem calling ValueCopy on the fetched item")
		}
		rr := bytes.NewReader(statusBytes)
		return status.FromBytes(rr)
	})
	if err != nil && err != badger.ErrKeyNotFound {
		return errors.Wrapf(err, "SnapshotStatus.ReadStatus: Problem reading status from db")
	}
	return nil
}

// IncrementMainDbSemaphoreMemoryLockRequired increments the MainDBSemaphore by one, it should be called with MemoryLock.
func (status *SnapshotStatus) IncrementMainDbSemaphoreMemoryLockRequired() {
	status.MainDBSemaphore++
	status.SaveStatus()
}

// IncrementAncestralDBSemaphoreMemoryLockRequired increments the AncestralDBSemaphore by one, it should be called with MemoryLock.
func (status *SnapshotStatus) IncrementAncestralDBSemaphoreMemoryLockRequired() {
	status.AncestralDBSemaphore++
	status.SaveStatus()
}

// IsFlushingToMainDBMemoryLockRequired checks if a flush to MainDB takes place. This should be called with MemoryLock.
func (status *SnapshotStatus) IsFlushingToMainDBMemoryLockRequired() bool {
	return status.MainDBSemaphore%2 == 1
}

// IsFlushingToAncestralMemoryLockRequired checks if a flush to AncestralDB takes place. This should be called with MemoryLock.
func (status *SnapshotStatus) IsFlushingToAncestralMemoryLockRequired() bool {
	return status.AncestralDBSemaphore%2 == 1
}

// IsFlushing checks whether a main DB flush or ancestral record flush is taking place.
func (status *SnapshotStatus) IsFlushing() bool {
	// We retrieve the ancestral record and main db semaphores.
	status.MemoryLock.Lock()
	defer status.MemoryLock.Unlock()

	return status.IsFlushingWithoutLock()
}

func (status *SnapshotStatus) IsFlushingWithoutLock() bool {
	// Flush is taking place if the semaphores have different counters or if they are odd.
	// We increment each semaphore whenever we start the flush and when we end it so they are always
	// even when the DB is not being updated.
	return status.MainDBSemaphore != status.AncestralDBSemaphore ||
		(status.MainDBSemaphore|status.AncestralDBSemaphore)%2 == 1
}

// GetSemaphores retrieves main and ancestral db semaphores.
func (status *SnapshotStatus) GetSemaphores() (_mainDbSemaphore uint64, _ancestralDBSemaphore uint64) {
	status.MemoryLock.Lock()
	defer status.MemoryLock.Unlock()

	return status.MainDBSemaphore, status.AncestralDBSemaphore
}

// -------------------------------------------------------------------------------------
// EncoderMigrationChecksum, EncoderMigration
// -------------------------------------------------------------------------------------

type EncoderMigrationChecksum struct {
	Checksum    *StateChecksum
	BlockHeight uint64

	Version   byte
	Completed bool
}

type EncoderMigration struct {
	migrationChecksums []*EncoderMigrationChecksum
	completed          bool
	currentBlockHeight uint64

	mainDb          *badger.DB
	snapshotDb      *badger.DB
	snapshotDbMutex *sync.Mutex
	params          *DeSoParams
}

func (migration *EncoderMigration) Initialize(mainDb *badger.DB, snapshotDb *badger.DB,
	snapshotDbMutex *sync.Mutex, blockHeight uint64, params *DeSoParams, disabled bool) error {

	migration.mainDb = mainDb
	migration.snapshotDb = snapshotDb
	migration.snapshotDbMutex = snapshotDbMutex
	migration.currentBlockHeight = blockHeight
	migration.params = params

	if snapshotDb == nil || snapshotDbMutex == nil {
		migration.snapshotDbMutex = &sync.Mutex{}
		return nil
	}

	migration.snapshotDbMutex.Lock()
	defer migration.snapshotDbMutex.Unlock()

	// For testing purposes we might want to disable migrations.
	if disabled {
		return nil
	}

	// Retrieve all migrations from the snapshot Db.
	err := migration.snapshotDb.View(func(txn *badger.Txn) error {
		item, err := txn.Get(_prefixMigrationStatus)
		if err != nil {
			return err
		}
		migrationBytes, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		rr := bytes.NewReader(migrationBytes)
		migrationLength, err := ReadUvarint(rr)
		if err != nil {
			return err
		}

		var migrationChecksums []*EncoderMigrationChecksum
		for ; migrationLength > 0; migrationLength-- {
			migrationChecksum := &EncoderMigrationChecksum{}
			// Initialize an empty checksum struct. We use it to parse checksum bytes.
			migrationChecksum.Checksum = &StateChecksum{}
			migrationChecksum.Checksum.Initialize(nil, nil)

			checksumBytes, err := DecodeByteArray(rr)
			if err != nil {
				return err
			}

			if err = migrationChecksum.Checksum.FromBytes(checksumBytes); err != nil {
				return err
			}
			if migrationChecksum.BlockHeight, err = ReadUvarint(rr); err != nil {
				return err
			}
			if migrationChecksum.Version, err = rr.ReadByte(); err != nil {
				return err
			}
			if migrationChecksum.Completed, err = ReadBoolByte(rr); err != nil {
				return err
			}

			// sanity-check that node has the same "version" of migration version map.
			exists := false
			for _, migrationHeight := range params.EncoderMigrationHeightsList {
				if migrationChecksum.BlockHeight == migrationHeight.Height &&
					migrationChecksum.Version == migrationHeight.Version {
					exists = true
				}
			}
			if !exists {
				return fmt.Errorf("there is no migration in EncoderMigrationHeightsList, seems like a schema error")
			}

			if migrationChecksum.BlockHeight > blockHeight {
				migrationChecksums = append(migrationChecksums, migrationChecksum)
			}
		}
		migration.migrationChecksums = migrationChecksums
		return nil
	})
	if err != nil && err != badger.ErrKeyNotFound {
		return errors.Wrapf(err, "EncoderMigrationChecksum.Initialize: Problem reading migration from db")
	}

	// Check if there are any outstanding migrations apart from the migrations we've saved in the db.
	// If so, add them to the migrationChecksums.
	for _, migrationHeight := range params.EncoderMigrationHeightsList {
		if migrationHeight.Height > blockHeight {
			exists := false
			for _, migrationChecksum := range migration.migrationChecksums {
				if migrationChecksum.BlockHeight == migrationHeight.Height {
					exists = true
					break
				}
			}
			if !exists {
				checksum := &StateChecksum{}
				checksum.Initialize(nil, nil)
				migration.migrationChecksums = append(migration.migrationChecksums, &EncoderMigrationChecksum{
					Checksum:    checksum,
					BlockHeight: migrationHeight.Height,
					Version:     migrationHeight.Version,
					Completed:   false,
				})
			}
		}
	}

	return nil
}

func (migration *EncoderMigration) InitializeSingleHeight(mainDb *badger.DB, snapshotDb *badger.DB,
	snapshotDbMutex *sync.Mutex, blockHeight uint64, params *DeSoParams) {

	migration.currentBlockHeight = blockHeight
	migration.mainDb = mainDb
	migration.snapshotDb = snapshotDb
	migration.snapshotDbMutex = snapshotDbMutex
	migration.params = params

	singleChecksum := &StateChecksum{}
	singleChecksum.Initialize(nil, nil)
	migration.migrationChecksums = append(migration.migrationChecksums, &EncoderMigrationChecksum{
		Checksum:    singleChecksum,
		BlockHeight: blockHeight,
		Version:     byte(0), // It's okay to put 0 here, because Version is never used directly.
		Completed:   false,
	})
}

func (migration *EncoderMigration) SaveMigrations() error {
	migration.snapshotDbMutex.Lock()
	defer migration.snapshotDbMutex.Unlock()

	var data []byte
	data = append(data, UintToBuf(uint64(len(migration.migrationChecksums)))...)
	for ii := range migration.migrationChecksums {
		checksumBytes, err := migration.migrationChecksums[ii].Checksum.ToBytes()
		if err != nil {
			return errors.Wrapf(err, "EncoderMigration.SaveMigrations: Problem getting migration checksum "+
				"bytes, ii = (%v)", ii)
		}
		data = append(data, EncodeByteArray(checksumBytes)...)
		data = append(data, UintToBuf(migration.migrationChecksums[ii].BlockHeight)...)
		data = append(data, migration.migrationChecksums[ii].Version)
		data = append(data, BoolToByte(migration.migrationChecksums[ii].Completed))
	}
	data = append(data, BoolToByte(migration.completed))

	return migration.snapshotDb.Update(func(txn *badger.Txn) error {
		return txn.Set(_prefixMigrationStatus, data)
	})
}

func (migration *EncoderMigration) StartMigrations() error {

	var outstandingChecksums []*EncoderMigrationChecksum

	// Look for any outstanding encoder migrations. These migrations are going to be set to not completed and their checksums
	// are set to identity (that's because we've set them to new migrations in Initialize).
	for _, migrationChecksum := range migration.migrationChecksums {
		if migrationChecksum.Completed && !migrationChecksum.Checksum.checksum.IsIdentity() {
			continue
		}

		migrationChecksum.Checksum.ResetChecksum()
		outstandingChecksums = append(outstandingChecksums, migrationChecksum)
	}
	if len(outstandingChecksums) == 0 {
		return nil
	}

	// If we get to this point, it means there are some new migrations that we need to process.
	glog.Infof(CLog(Yellow, fmt.Sprintf("EncoderMigration: Found %v outstanding migrations. Proceeding to scan through the "+
		"blockchain state. This is a one-time database update. It wouldn't be a good idea to terminate the node now. "+
		"This might take a while...", len(outstandingChecksums))))

	// Get all state prefixes and sort them.
	var prefixes [][]byte
	for prefix, isState := range StatePrefixes.StatePrefixesMap {
		if !isState {
			continue
		}
		prefixes = append(prefixes, []byte{prefix})
	}
	sort.Slice(prefixes, func(ii, jj int) bool {
		return prefixes[ii][0] < prefixes[jj][0]
	})

	// Iterate through the whole db and re-calculate the checksum according to the outstanding migrations.
	// TODO: Check if parallel gets are faster on fully synced node.
	carrierChecksum := &StateChecksum{}
	carrierChecksum.Initialize(nil, nil)

	// This whole thing is just a status printer
	startedPrefix := prefixes[0]
	finishChannel := make(chan struct{})
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-finishChannel:
				return
			case <-ticker.C:
				var completedPrefixes [][]byte
				var incompletePrefixes [][]byte
				var currentPrefix []byte

				for _, prefix := range StatePrefixes.StatePrefixesList {
					if prefix[0] < startedPrefix[0] {
						completedPrefixes = append(completedPrefixes, prefix)
					} else if prefix[0] == startedPrefix[0] {
						currentPrefix = startedPrefix[:]
					} else {
						incompletePrefixes = append(incompletePrefixes, prefix)
					}
				}
				if len(completedPrefixes) > 0 {
					glog.Infof(CLog(Green, fmt.Sprintf("EncoderMigration: finished updating prefixes (%v)", completedPrefixes)))
				}
				if len(currentPrefix) > 0 {
					glog.Infof(CLog(Yellow, fmt.Sprintf("EncoderMigration: currently updating prefix: (%v)", currentPrefix)))
				}
				if len(incompletePrefixes) > 0 {
					glog.Infof("Remaining prefixes (%v)", incompletePrefixes)
				}
			}
		}
	}()

	// Compute the checksums for all migrations, as needed.
	err := migration.mainDb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		for _, prefix := range prefixes {
			startedPrefix = prefix
			it := txn.NewIterator(opts)
			for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
				item := it.Item()
				key := item.Key()
				err := item.Value(func(value []byte) error {
					return carrierChecksum.AddOrRemoveBytesWithMigrations(key, value, migration.currentBlockHeight,
						outstandingChecksums, true)
				})
				if err != nil {
					return err
				}
			}
			it.Close()
		}
		return nil
	})
	close(finishChannel)
	if err != nil {
		return errors.Wrapf(err, "EncoderMigration.StartMigrations: Something went wrong during "+
			"the encoder migration. Node should be restarted.")
	}
	if err = carrierChecksum.Wait(); err != nil {
		return errors.Wrapf(err, "EncoderMigration.StartMigrations: Problem waiting for the checksum. "+
			"Node should be restarted.")
	}
	glog.Infof(CLog(Yellow, "Finished computing the migration"))

	for _, migrationChecksum := range migration.migrationChecksums {
		migrationChecksum.Completed = true
	}
	migration.completed = true
	return nil
}

func (migration *EncoderMigration) GetMigrationChecksumAtBlockheight(blockHeight uint64) *StateChecksum {
	for _, migrationChecksum := range migration.migrationChecksums {
		if migrationChecksum.BlockHeight == blockHeight {
			return migrationChecksum.Checksum
		}
	}
	return nil
}

func (migration *EncoderMigration) CleanupMigrations(blockHeight uint64) {
	for jj := 0; jj < len(migration.migrationChecksums); jj++ {
		if migration.migrationChecksums[jj].BlockHeight <= blockHeight {
			migration.migrationChecksums = append(migration.migrationChecksums[:jj],
				migration.migrationChecksums[jj+1:]...)
			jj--
		}
	}
}

func (migration *EncoderMigration) ResetChecksums() {
	for _, migrationChecksum := range migration.migrationChecksums {
		migrationChecksum.Checksum.ResetChecksum()
		migrationChecksum.Completed = false
	}
}

// -------------------------------------------------------------------------------------
// Timer
// -------------------------------------------------------------------------------------

// Mode determines if Timer will be used by the node. Set --time-events=true to enable timing.
var Mode = DisableTimer

// Timer is used for convenience to time certain events during development.
// NOTE: Timer uses maps and so doesn't support concurrent calls to Start() or End().
type Timer struct {
	totalElapsedTimes map[string]float64
	lastTimes         map[string]time.Time
	mode              bool
	mut               sync.RWMutex
}

func (t *Timer) Initialize() {
	t.totalElapsedTimes = make(map[string]float64)
	t.lastTimes = make(map[string]time.Time)
	// Comment this to stop timing
	t.mode = Mode
}

func (t *Timer) Start(eventName string) {
	if t.mode != EnableTimer {
		return
	}

	t.mut.Lock()
	defer t.mut.Unlock()
	if _, exists := t.lastTimes[eventName]; !exists {
		t.totalElapsedTimes[eventName] = 0.0
	}
	t.lastTimes[eventName] = time.Now()
}

func (t *Timer) End(eventName string) {
	if t.mode != EnableTimer {
		return
	}

	t.mut.Lock()
	defer t.mut.Unlock()
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

	t.mut.RLock()
	defer t.mut.RUnlock()
	if _, exists := t.lastTimes[eventName]; exists {
		glog.Infof("Timer.End: event (%s) total elapsed time (%v)",
			eventName, t.totalElapsedTimes[eventName])
	}
}

// -------------------------------------------------------------------------------------
// Color Logger
// -------------------------------------------------------------------------------------

var (
	Cyan    = color.New(color.FgCyan)
	Magenta = color.New(color.FgMagenta)
	Yellow  = color.New(color.FgHiYellow)
	Green   = color.New(color.FgHiGreen)
	Blue    = color.New(color.FgBlue)
	Red     = color.New(color.FgRed)
)

func CLog(c *color.Color, str string) string {
	return c.Sprint(str)
}
