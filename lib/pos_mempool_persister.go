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
	DbMempoolContextId = "mempool-transactions"
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

type MempoolPersister struct {
	sync.Mutex
	stopGroup sync.WaitGroup

	status      MempoolPersisterStatus
	dbCtx       *storage.DatabaseContext
	eventQueue  chan *MempoolEvent
	updateBatch []*MempoolEvent
}

func NewMempoolPersister(dbCtx *storage.DatabaseContext) *MempoolPersister {
	return &MempoolPersister{
		status:     MempoolPersisterStatusNotRunning,
		dbCtx:      dbCtx,
		eventQueue: make(chan *MempoolEvent, eventQueueSize),
	}
}

func (mp *MempoolPersister) Start() {
	mp.Reset()
	mp.stopGroup.Add(1)
	mp.status = MempoolPersisterStatusRunning
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

		case <-time.After(30 * time.Second):
			if err := mp.PersistBatch(); err != nil {
				glog.Errorf("MempoolPersister: Error persisting batch: %v", err)
			}
		}
	}
}

func (mp *MempoolPersister) Stop() error {
	mp.eventQueue <- &MempoolEvent{Type: MempoolEventExit}
	mp.stopGroup.Wait()
	if err := mp.PersistBatch(); err != nil {
		return errors.Wrapf(err, "MempoolPersister: Error persisting batch")
	}
	mp.Reset()
	return nil
}

func (mp *MempoolPersister) PersistBatch() error {
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

			if event.Type == MempoolEventAdd {
				txn.Set(key, value, ctx)
			} else if event.Type == MempoolEventRemove {
				txn.Delete(key, ctx)
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

func (mp *MempoolPersister) Reset() {
	mp.Lock()
	defer mp.Unlock()

	mp.updateBatch = nil
	mp.eventQueue = make(chan *MempoolEvent, eventQueueSize)
}
