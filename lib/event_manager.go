package lib

import "github.com/google/uuid"

type TransactionEventFunc func(event *TransactionEvent)
type DBTransactionEventFunc func(event *DBTransactionEvent)
type DBFlushedEventFunc func(event *DBFlushedEvent)
type BlockEventFunc func(event *BlockEvent)
type SnapshotCompletedEventFunc func()

// DBTransactionEvent is an event that is fired when an entry is connected or disconnected from the badger db.
type DBTransactionEvent struct {
	// The details needed to represent this state change to a data consumer.
	StateChangeEntry *StateChangeEntry
	// An ID to map the event to the db flush that it is included in.
	FlushId uuid.UUID
	// Whether the transaction is from the mempool or a confirmed transaction.
	IsMempoolTxn bool
}

// DBFlushedEvent is an event that is fired when the badger db is flushed.
type DBFlushedEvent struct {
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
	CommittedFlushId uuid.UUID
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
}

type EventManager struct {
	transactionConnectedHandlers   []TransactionEventFunc
	dbTransactionConnectedHandlers []DBTransactionEventFunc
	dbFlushedHandlers              []DBFlushedEventFunc
	blockConnectedHandlers         []BlockEventFunc
	blockDisconnectedHandlers      []BlockEventFunc
	blockAcceptedHandlers          []BlockEventFunc
	snapshotCompletedHandlers      []SnapshotCompletedEventFunc
}

func NewEventManager() *EventManager {
	return &EventManager{}
}

func (em *EventManager) OnDbTransactionConnected(handler DBTransactionEventFunc) {
	em.dbTransactionConnectedHandlers = append(em.dbTransactionConnectedHandlers, handler)
}

func (em *EventManager) OnDbFlushed(handler DBFlushedEventFunc) {
	em.dbFlushedHandlers = append(em.dbFlushedHandlers, handler)
}

func (em *EventManager) dbTransactionConnected(event *DBTransactionEvent) {
	for _, handler := range em.dbTransactionConnectedHandlers {
		handler(event)
	}
}

func (em *EventManager) dbFlushed(event *DBFlushedEvent) {
	for _, handler := range em.dbFlushedHandlers {
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
