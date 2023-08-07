package lib

import (
	"bytes"
	"github.com/deso-protocol/core/storage"
	"github.com/golang/glog"
	"github.com/pkg/errors"
	"sync"
	"time"
)

const (
	DbMempoolContextId = "transactions"
	eventQueueSize     = 10000
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

// MempoolPersister is responsible for persisting transactions in the mempool to the database. Whenever a transaction is
// added or removed from the mempool, the MempoolPersister is notified via the OnMempoolEvent callback. The Persister
// will then add the event to a queue. Periodically, the transaction queue is flushed to the database and all the cached
// transactions are persisted. To achieve this, the persister runs its own goroutine.
type MempoolPersister struct {
	sync.Mutex
	status MempoolPersisterStatus

	// db is the database that the persister will write transactions to.
	db storage.Database

	// stopGroup and startGroup are used to manage the synchronization of the run loop.
	stopGroup  sync.WaitGroup
	startGroup sync.WaitGroup

	// batchPersistFrequencyMilliseconds is the time frequency at which the persister will flush the transaction queue to the database.
	batchPersistFrequencyMilliseconds int
	// eventQueue is used to queue up transactions to be persisted. The queue receives events from the OnMempoolEvent,
	// which is called whenever a transaction is added or removed from the mempool.
	eventQueue chan *MempoolEvent
	// updateBatch is used to cache transactions that need to be persisted to the database. The batch is flushed to the
	// database periodically based on the batchPersistFrequencyMilliseconds.
	updateBatch []*MempoolEvent
}

func NewMempoolPersister(db storage.Database, batchPersistFrequencyMilliseconds int) *MempoolPersister {
	return &MempoolPersister{
		batchPersistFrequencyMilliseconds: batchPersistFrequencyMilliseconds,
		status:                            MempoolPersisterStatusNotRunning,
		db:                                db,
		eventQueue:                        make(chan *MempoolEvent, eventQueueSize),
	}
}

// Start is the entry point for the MempoolPersister. It starts the run loop and begins persisting transactions to the database.
func (mp *MempoolPersister) Start() {
	if mp.status == MempoolPersisterStatusRunning {
		return
	}

	// Make sure the persister is cleared before starting.
	mp.reset()
	// We use syncGroups to synchronize the persister thread. The stop group is used to wait for the persister to stop
	// the run loop. The start group is used to wait for the persister goroutine allocation.
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

		case <-time.After(time.Duration(mp.batchPersistFrequencyMilliseconds) * time.Millisecond):
			if err := mp.persistBatch(); err != nil {
				glog.Errorf("MempoolPersister: Error persisting batch: %v", err)
			}
			continue
		}
	}
}

// Stop is used to stop the persister thread and reset the persister state. It will wait for the persister thread to
// flush the outstanding updateBatch to the database before returning.
func (mp *MempoolPersister) Stop() error {
	if mp.status == MempoolPersisterStatusNotRunning {
		return nil
	}
	// Enqueue the exit event and wait for the persister thread to stop.
	mp.eventQueue <- &MempoolEvent{Type: MempoolEventExit}
	mp.stopGroup.Wait()
	// Persist any outstanding transactions.
	if err := mp.persistBatch(); err != nil {
		return errors.Wrapf(err, "MempoolPersister: Error persisting batch")
	}
	// Reset the persister state.
	mp.reset()
	mp.status = MempoolPersisterStatusNotRunning
	return nil
}

// persistBatch is used to flush the updateBatch to the database. It will iterate through the updateBatch and add or remove
// transactions from the database based on the event type. Error is returned if the persister is not running or if there
// is an error persisting the batch.
func (mp *MempoolPersister) persistBatch() error {
	if mp.status == MempoolPersisterStatusNotRunning {
		return nil
	}

	mp.Lock()
	defer mp.Unlock()

	// If there are no transactions to persist, return.
	if len(mp.updateBatch) == 0 {
		return nil
	}

	err := mp.db.Update(func(txn storage.Transaction) error {
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
				if err := txn.Set(key, value); err != nil {
					glog.Errorf("MempoolPersister: Error setting key: %v", err)
				}
			case MempoolEventRemove:
				if err := txn.Delete(key); err != nil {
					glog.Errorf("MempoolPersister: Error deleting key: %v", err)
				}
			}
		}
		return nil
	})
	mp.updateBatch = nil

	if err != nil {
		return errors.Wrapf(err, "MempoolPersister: Error persisting batch")
	}
	return nil
}

// GetPersistedTransactions is used to retrieve all transactions from the database. It will return an error if the persister
// is not currently running or if there was an issue retrieving the transactions.
func (mp *MempoolPersister) GetPersistedTransactions() ([]*MempoolTx, error) {
	if mp.status == MempoolPersisterStatusNotRunning {
		return nil, errors.Wrapf(MempoolErrorNotRunning, "MempoolPersister: Cannot retrieve transactions while running")
	}

	mp.Lock()
	defer mp.Unlock()

	var mempoolTxns []*MempoolTx
	err := mp.db.View(func(txn storage.Transaction) error {
		// Iterate through the transaction records in the database.
		iter, err := txn.GetIterator([]byte{})
		if err != nil {
			return errors.Wrapf(err, "MempoolPersister: Error retrieving iterator")
		}
		defer iter.Close()
		for iter.Next() {
			txnBytes, err := iter.Value()
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

// OnMempoolEvent is used to add a transaction event to the eventQueue.
func (mp *MempoolPersister) OnMempoolEvent(event *MempoolEvent) {
	if mp.eventQueue == nil {
		return
	}
	mp.eventQueue <- event
}

// reset is used to clear the persister state.
func (mp *MempoolPersister) reset() {
	mp.Lock()
	defer mp.Unlock()

	mp.updateBatch = nil
	mp.eventQueue = make(chan *MempoolEvent, eventQueueSize)
}
