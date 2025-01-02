package lib

import (
	"bytes"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/golang/glog"
	"github.com/pkg/errors"
)

const (
	eventQueueSize = 10000
)

type MempoolEventType int

const (
	MempoolEventAdd MempoolEventType = iota
	MempoolEventRemove
	MempoolEventExit
)

type MempoolPersisterStatus int

const (
	MempoolPersisterStatusRunning MempoolPersisterStatus = iota
	MempoolPersisterStatusNotRunning
)

type MempoolEvent struct {
	Txn  *MempoolTx
	Type MempoolEventType
}

// MempoolPersister is responsible for persisting transactions in the mempool to the database. Whenever a transaction is
// added or removed from the mempool, the MempoolPersister is notified via the EnqueueEvent callback. The Persister
// will then add the event to a queue. Periodically, the transaction queue is flushed to the database and all the cached
// transactions are persisted. To achieve this, the persister runs its own goroutine.
type MempoolPersister struct {
	sync.RWMutex
	status MempoolPersisterStatus

	// db is the database that the persister will write transactions to.
	db *badger.DB

	// stopGroup and startGroup are used to manage the synchronization of the run loop.
	stopGroup  sync.WaitGroup
	startGroup sync.WaitGroup

	// mempoolBackupIntervalMillis is the time frequency at which the persister will flush the transaction queue to the database.
	mempoolBackupIntervalMillis int
	// eventQueue is used to queue up transactions to be persisted. The queue receives events from the EnqueueEvent,
	// which is called whenever a transaction is added or removed from the mempool.
	eventQueue chan *MempoolEvent
	// updateBatch is used to cache transactions that need to be persisted to the database. The batch is flushed to the
	// database periodically based on the mempoolBackupIntervalMillis.
	updateBatch []*MempoolEvent
}

func NewMempoolPersister(db *badger.DB, mempoolBackupIntervalMillis int) *MempoolPersister {
	return &MempoolPersister{
		mempoolBackupIntervalMillis: mempoolBackupIntervalMillis,
		status:                      MempoolPersisterStatusNotRunning,
		db:                          db,
		eventQueue:                  make(chan *MempoolEvent, eventQueueSize),
	}
}

// Start is the entry point for the MempoolPersister. It starts the run loop and begins persisting transactions to the database.
func (mp *MempoolPersister) Start() {
	mp.Lock()
	defer mp.Unlock()

	if mp.IsRunning() {
		return
	}

	// Make sure the persister is cleared before starting.
	mp.reset()
	// We use syncGroups to synchronize the persister thread. The stop group is used to wait for the persister to stop
	// the run loop. The start group is used to wait for the persister goroutine allocation. Note that the startGroup is
	// used to ensure that the run() goroutine has been allocated a thread before returning from Start().
	mp.stopGroup.Add(1)
	mp.startGroup.Add(1)
	// Run the persister in a goroutine.
	go mp.run()
	// Wait for the persister goroutine to start.
	mp.startGroup.Wait()
	mp.status = MempoolPersisterStatusRunning
}

// run is the main even loop for the MempoolPersister thread.
func (mp *MempoolPersister) run() {
	mp.startGroup.Done()
	// The run loop will run until a MempoolEventExit is received. The main actions of the run loop are to either
	// add a new transaction event to the updateBatch or to flush the updateBatch to the database.
	for {
		select {
		case event := <-mp.eventQueue:
			switch event.Type {
			case MempoolEventAdd, MempoolEventRemove:
				mp.Lock()
				mp.updateBatch = append(mp.updateBatch, event)
				mp.Unlock()

			case MempoolEventExit:
				close(mp.eventQueue)
				mp.stopGroup.Done()
				return
			}
			continue

		case <-time.After(time.Duration(mp.mempoolBackupIntervalMillis) * time.Millisecond):
			if err := mp.persistBatch(); err != nil {
				glog.Errorf("MempoolPersister: Error persisting batch: %v", err)
			}
			continue
		}
	}
}

// Stop is used to stop the persister thread and reset the persister state. It will wait for the persister thread to
// flush the outstanding updateBatch to the database before returning. Stop should not be called in concurrent threads.
func (mp *MempoolPersister) Stop() error {
	mp.Lock()
	if !mp.IsRunning() {
		return nil
	}
	mp.Unlock()

	// Enqueue the exit event and wait for the persister thread to stop.
	event := &MempoolEvent{Type: MempoolEventExit}
	mp.EnqueueEvent(event)
	mp.stopGroup.Wait()

	// Persist any outstanding transactions.
	if err := mp.persistBatchNoLock(); err != nil {
		return errors.Wrapf(err, "MempoolPersister: Error persisting batch")
	}
	// Reset the persister state.
	mp.reset()
	mp.status = MempoolPersisterStatusNotRunning
	return nil
}

func (mp *MempoolPersister) IsRunning() bool {
	return mp.status == MempoolPersisterStatusRunning
}

// persistBatch is used to flush the updateBatch to the database. It will iterate through the updateBatch and add or remove
// transactions from the database based on the event type. Error is returned if the persister is not running or if there
// is an error persisting the batch.
func (mp *MempoolPersister) persistBatch() error {
	mp.Lock()
	defer mp.Unlock()

	if !mp.IsRunning() {
		return nil
	}

	return mp.persistBatchNoLock()
}

func (mp *MempoolPersister) persistBatchNoLock() error {
	if !mp.IsRunning() {
		return nil
	}

	glog.V(0).Infof("MempoolPersister: Persisting batch of %d mempool events", len(mp.updateBatch))

	// If there are no transactions to persist, return.
	if len(mp.updateBatch) == 0 {
		return nil
	}

	wb := mp.db.NewWriteBatch()
	defer wb.Cancel()

	addEvents, removeEvents := 0, 0
	for _, event := range mp.updateBatch {
		if event.Txn == nil || event.Txn.Hash == nil {
			continue
		}
		// The transactions are stored in a KV database. The key is the transaction hash and the value is the
		// serialized transaction.
		key := event.Txn.Hash.ToBytes()
		value, err := event.Txn.ToBytes()
		if err != nil {
			continue
		}

		// Set or delete a record based on the event type.
		switch event.Type {
		case MempoolEventAdd:
			if err := wb.Set(key, value); err != nil {
				glog.Errorf("MempoolPersister: Error setting key: %v", err)
			}
			addEvents++
		case MempoolEventRemove:
			if err := wb.Delete(key); err != nil {
				glog.Errorf("MempoolPersister: Error deleting key: %v", err)
			}
			removeEvents++
		}
	}
	err := wb.Flush()
	if err != nil {
		return errors.Wrapf(err, "MempoolPersister: Error persisting batch")
	}

	mp.updateBatch = nil

	glog.V(0).Infof("MempoolPersister: Persisted %d add events and %d remove events", addEvents, removeEvents)

	return nil
}

// GetPersistedTransactions is used to retrieve all transactions from the database. It will return an error if the persister
// is not currently running or if there was an issue retrieving the transactions.
func (mp *MempoolPersister) GetPersistedTransactions() ([]*MempoolTx, error) {
	mp.RLock()
	defer mp.RUnlock()

	if !mp.IsRunning() {
		return nil, errors.Wrapf(MempoolErrorNotRunning, "MempoolPersister: Cannot retrieve transactions while not running")
	}

	var mempoolTxns []*MempoolTx
	err := mp.db.View(func(txn *badger.Txn) error {
		// Iterate through the transaction records in the database.
		iter := txn.NewIterator(badger.DefaultIteratorOptions)
		defer iter.Close()
		for iter.Seek([]byte{}); iter.Valid(); iter.Next() {
			item := iter.Item()
			txnBytes, err := item.ValueCopy(nil)
			if err != nil {
				return errors.Wrapf(err, "MempoolPersister: Error retrieving value")
			}

			rr := bytes.NewReader(txnBytes)
			mempoolTx := &MempoolTx{}
			if err := mempoolTx.FromBytes(rr); err != nil {
				return errors.Wrapf(err, "MempoolPersister: Error retrieving txn")
			}
			mempoolTxns = append(mempoolTxns, mempoolTx)
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrapf(err, "MempoolPersister: Error retrieving transactions")
	}
	return mempoolTxns, nil
}

// EnqueueEvent is used to add a transaction event to the eventQueue.
func (mp *MempoolPersister) EnqueueEvent(event *MempoolEvent) {
	if mp.eventQueue == nil {
		return
	}
	mp.eventQueue <- event
}

// reset is used to clear the persister state.
func (mp *MempoolPersister) reset() {
	mp.updateBatch = nil
	mp.eventQueue = make(chan *MempoolEvent, eventQueueSize)
}
