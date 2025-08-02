package lib

import (
	"github.com/dgraph-io/badger/v3"
	"github.com/google/uuid"
)

type TransactionEventFunc func(event *TransactionEvent)
type StateSyncerOperationEventFunc func(event *StateSyncerOperationEvent)
type StateSyncerFlushedEventFunc func(event *StateSyncerFlushedEvent)
type BlockEventFunc func(event *BlockEvent)
type SnapshotCompletedEventFunc func()

// StateSyncerOperationEvent is an event that is fired when an entry is connected or disconnected from the badger db.
type StateSyncerOperationEvent struct {
	// The details needed to represent this state change to a data consumer.
	StateChangeEntry *StateChangeEntry
	// An ID to map the event to the db flush that it is included in.
	FlushId uuid.UUID
	// Whether the transaction is from the mempool or a confirmed transaction.
	IsMempoolTxn bool
}

// StateSyncerFlushedEvent is an event that is fired when the badger db is flushed.
type StateSyncerFlushedEvent struct {
	// The id of the flush.
	// Note that when blocksyncing, everything runs on a single thread, so the UUID.Nil value is used, since
	// there is only ever one flush, so disambiguating them is unnecessary.
	FlushId uuid.UUID
	// Whether the flush succeeded or not.
	Succeeded bool
	// Whether the flush is from the mempool or a confirmed transaction.
	IsMempoolFlush bool
	// For mempool flushes, the flush id of the last confirmed flush when the mempool connect was initialized.
	// If this has since changed, throw out the mempool flush.
	BlockSyncFlushId uuid.UUID
}

type TransactionEvent struct {
	Txn     *MsgDeSoTxn
	TxnHash *BlockHash

	// Optional
	UtxoView *UtxoView
	UtxoOps  []*UtxoOperation
}

type BlockEvent struct {
	Block *MsgDeSoBlock

	// Optional
	UtxoView *UtxoView
	UtxoOps  [][]*UtxoOperation
	PreCommitTxn *badger.Txn
}

type EventManager struct {
	transactionConnectedHandlers []TransactionEventFunc
	stateSyncerOperationHandlers []StateSyncerOperationEventFunc
	stateSyncerFlushedHandlers   []StateSyncerFlushedEventFunc
	blockConnectedHandlers       []BlockEventFunc
	blockDisconnectedHandlers    []BlockEventFunc
	blockCommittedHandlers       []BlockEventFunc
	blockAcceptedHandlers        []BlockEventFunc
	snapshotCompletedHandlers    []SnapshotCompletedEventFunc
	// A transaction used by the state syncer mempool routine to reference the state of the badger db
	// prior to flushing mempool transactions. This represents the last committed view of the db.
	lastCommittedViewTxn *badger.Txn
	isMempoolManager     bool
}

func NewEventManager() *EventManager {
	return &EventManager{}
}

func (em *EventManager) OnStateSyncerOperation(handler StateSyncerOperationEventFunc) {
	em.stateSyncerOperationHandlers = append(em.stateSyncerOperationHandlers, handler)
}

func (em *EventManager) OnStateSyncerFlushed(handler StateSyncerFlushedEventFunc) {
	em.stateSyncerFlushedHandlers = append(em.stateSyncerFlushedHandlers, handler)
}

func (em *EventManager) stateSyncerOperation(event *StateSyncerOperationEvent) {
	for _, handler := range em.stateSyncerOperationHandlers {
		handler(event)
	}
}

func (em *EventManager) stateSyncerFlushed(event *StateSyncerFlushedEvent) {
	for _, handler := range em.stateSyncerFlushedHandlers {
		handler(event)
	}
}

func (em *EventManager) OnTransactionConnected(handler TransactionEventFunc) {
	em.transactionConnectedHandlers = append(em.transactionConnectedHandlers, handler)
}

func (em *EventManager) transactionConnected(event *TransactionEvent) {
	for _, handler := range em.transactionConnectedHandlers {
		handler(event)
	}
}

func (em *EventManager) OnBlockCommitted(handler BlockEventFunc) {
	em.blockCommittedHandlers = append(em.blockCommittedHandlers, handler)
}

func (em *EventManager) blockCommitted(event *BlockEvent) {
	for _, handler := range em.blockCommittedHandlers {
		handler(event)
	}
}

func (em *EventManager) OnBlockConnected(handler BlockEventFunc) {
	em.blockConnectedHandlers = append(em.blockConnectedHandlers, handler)
}

func (em *EventManager) blockConnected(event *BlockEvent) {
	for _, handler := range em.blockConnectedHandlers {
		handler(event)
	}
}

func (em *EventManager) OnBlockDisconnected(handler BlockEventFunc) {
	em.blockDisconnectedHandlers = append(em.blockDisconnectedHandlers, handler)
}

func (em *EventManager) blockDisconnected(event *BlockEvent) {
	for _, handler := range em.blockDisconnectedHandlers {
		handler(event)
	}
}

func (em *EventManager) OnSnapshotCompleted(handler SnapshotCompletedEventFunc) {
	em.snapshotCompletedHandlers = append(em.snapshotCompletedHandlers, handler)
}

func (em *EventManager) snapshotCompleted() {
	for _, handler := range em.snapshotCompletedHandlers {
		handler()
	}
}

func (em *EventManager) OnBlockAccepted(handler BlockEventFunc) {
	em.blockAcceptedHandlers = append(em.blockAcceptedHandlers, handler)
}

func (em *EventManager) blockAccepted(event *BlockEvent) {
	for _, handler := range em.blockAcceptedHandlers {
		handler(event)
	}
}
