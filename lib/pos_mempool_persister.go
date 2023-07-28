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
// transactions are persisted.
type MempoolPersister struct {
	sync.Mutex
	stopGroup  sync.WaitGroup
	startGroup sync.WaitGroup

	frequencyMilliseconds int
	status                MempoolPersisterStatus
	dbCtx                 *storage.DatabaseContext
	eventQueue            chan *MempoolEvent
	updateBatch           []*MempoolEvent
}

func NewMempoolPersister(dbCtx *storage.DatabaseContext, frequencyMilliseconds int) *MempoolPersister {
	return &MempoolPersister{
		frequencyMilliseconds: frequencyMilliseconds,
		status:                MempoolPersisterStatusNotRunning,
		dbCtx:                 dbCtx,
		eventQueue:            make(chan *MempoolEvent, eventQueueSize),
	}
}

func (mp *MempoolPersister) Start() {
	if mp.status == MempoolPersisterStatusRunning {
		return
	}

	mp.reset()
	mp.stopGroup.Add(1)
	mp.startGroup.Add(1)
	go mp.run()
	mp.startGroup.Wait()
	mp.status = MempoolPersisterStatusRunning
}

func (mp *MempoolPersister) run() {
	mp.startGroup.Done()
	for {
		select {
		case event := <-mp.eventQueue:
			switch event.Type {
			case MempoolEventAdd, MempoolEventRemove:
				mp.Lock()
				mp.updateBatch = append(mp.updateBatch, event)
				mp.Unlock()

			case MempoolEventExit:
				mp.status = MempoolPersisterStatusNotRunning
				mp.stopGroup.Done()
				return
			}
			continue

		case <-time.After(time.Duration(mp.frequencyMilliseconds) * time.Millisecond):
			if err := mp.persistBatch(); err != nil {
				glog.Errorf("MempoolPersister: Error persisting batch: %v", err)
			}
			continue
		}
	}
}

func (mp *MempoolPersister) Stop() error {
	if mp.status == MempoolPersisterStatusNotRunning {
		return nil
	}
	mp.eventQueue <- &MempoolEvent{Type: MempoolEventExit}
	mp.stopGroup.Wait()
	if err := mp.persistBatch(); err != nil {
		return errors.Wrapf(err, "MempoolPersister: Error persisting batch")
	}
	mp.reset()
	return nil
}

func (mp *MempoolPersister) persistBatch() error {
	if mp.status == MempoolPersisterStatusNotRunning {
		return nil
	}

	mp.Lock()
	defer mp.Unlock()

	if len(mp.updateBatch) == 0 {
		return nil
	}

	localContext := mp.dbCtx.GetContext([]byte(DbMempoolContextId))
	err := mp.dbCtx.Update(localContext, func(txn storage.Transaction, ctx storage.Context) error {
		for _, event := range mp.updateBatch {
			if event.Txn == nil || event.Txn.Hash == nil {
				continue
			}
			key := event.Txn.Hash.ToBytes()
			value, err := event.Txn.ToBytes()
			if err != nil {
				continue
			}

			switch event.Type {
			case MempoolEventAdd:
				if err := txn.Set(key, value, ctx); err != nil {
					glog.Errorf("MempoolPersister: Error setting key: %v", err)
				}
			case MempoolEventRemove:
				if err := txn.Delete(key, ctx); err != nil {
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

func (mp *MempoolPersister) RetrieveTransactions() ([]*MempoolTx, error) {
	if mp.status == MempoolPersisterStatusNotRunning {
		return nil, errors.Wrapf(MempoolErrorNotRunning, "MempoolPersister: Cannot retrieve transactions while running")
	}

	mp.Lock()
	defer mp.Unlock()

	var mempoolTxns []*MempoolTx
	localContext := mp.dbCtx.GetContext([]byte(DbMempoolContextId))
	err := mp.dbCtx.View(localContext, func(txn storage.Transaction, ctx storage.Context) error {
		iter, err := txn.GetIterator(ctx)
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

func (mp *MempoolPersister) OnMempoolEvent(event *MempoolEvent) {
	if mp.eventQueue == nil {
		return
	}
	mp.eventQueue <- event
}

func (mp *MempoolPersister) reset() {
	mp.Lock()
	defer mp.Unlock()

	mp.updateBatch = nil
	mp.eventQueue = make(chan *MempoolEvent, eventQueueSize)
}
