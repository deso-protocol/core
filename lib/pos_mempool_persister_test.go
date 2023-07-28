package lib

import (
	"github.com/deso-protocol/core/storage"
	"github.com/stretchr/testify/require"
	"math/rand"
	"os"
	"testing"
	"time"
)

func TestMempoolPersister(t *testing.T) {
	require := require.New(t)

	seed := int64(177)
	testCases := 1000
	addRemoveCases := 100
	feeRange := uint64(10000)
	timestampRange := uint64(10000)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()

	// Generate a set of random mempool transactions.
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, 1000, timestampRange, testCases)

	// Create a new mempool persister.
	dir, err := os.MkdirTemp("", "badgerdb-persister")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := storage.DefaultBadgerOptions(dir)
	db := storage.NewBadgerDatabase(opts, false)
	require.NoError(db.Setup())
	defer db.Erase()
	defer db.Close()

	ctx := db.GetContext(nil)
	dbCtx := storage.NewDatabaseContext(db, ctx)

	mempoolPersister := NewMempoolPersister(dbCtx, 100)

	// Start the mempool persister.
	mempoolPersister.Start()

	// Create an event manager
	eventManager := NewEventManager()
	eventManager.OnMempoolEvent(mempoolPersister.OnMempoolEvent)

	defer mempoolPersister.Stop()

	// Add all the transactions to the mempool.
	for _, txn := range txnPool {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		eventManager.mempoolEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err := mempoolPersister.RetrieveTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Add the same transactions again and ensure there are no overlaps.
	for ii := 0; ii < addRemoveCases; ii++ {
		event := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventAdd,
		}
		eventManager.mempoolEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err = mempoolPersister.RetrieveTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Remove couple transactions from the mempool
	for ii := 0; ii < addRemoveCases; ii++ {
		event := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventRemove,
		}
		eventManager.mempoolEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err = mempoolPersister.RetrieveTransactions()
	require.NoError(err)
	require.Equal(len(txnPool)-addRemoveCases, len(retrievedTxns))

	// Add & Remove some transactions again and ensure transactions were really removed.
	for ii := 0; ii < addRemoveCases; ii++ {
		event := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventAdd,
		}
		eventManager.mempoolEvent(event)

		event2 := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventRemove,
		}
		eventManager.mempoolEvent(event2)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err = mempoolPersister.RetrieveTransactions()
	require.NoError(err)
	require.Equal(len(txnPool)-addRemoveCases, len(retrievedTxns))
}

func TestMempoolPersisterRestart(t *testing.T) {
	require := require.New(t)

	seed := int64(178)
	feeRange := uint64(10000)
	testCases := 100
	timestampRange := uint64(10000)
	rand := rand.New(rand.NewSource(seed))
	globalParams := _testGetDefaultGlobalParams()

	// Generate a set of random mempool transactions.
	txnPool := _testGetRandomMempoolTxns(rand, globalParams.MinimumNetworkFeeNanosPerKB, feeRange, 1000, timestampRange, testCases)

	// Create a new mempool persister.
	dir, err := os.MkdirTemp("", "badgerdb-persister")
	t.Logf("BadgerDB directory: %s\nIt should be automatically removed at the end of the test", dir)
	require.NoError(err)

	opts := storage.DefaultBadgerOptions(dir)
	db := storage.NewBadgerDatabase(opts, false)
	require.NoError(db.Setup())

	ctx := db.GetContext(nil)
	dbCtx := storage.NewDatabaseContext(db, ctx)

	mempoolPersister := NewMempoolPersister(dbCtx, 100)

	// Start the mempool persister.
	mempoolPersister.Start()

	// Create an event manager
	eventManager := NewEventManager()
	eventManager.OnMempoolEvent(mempoolPersister.OnMempoolEvent)

	// Add all the transactions to the mempool.
	for _, txn := range txnPool {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		eventManager.mempoolEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err := mempoolPersister.RetrieveTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Stop the mempool persister.
	require.NoError(mempoolPersister.Stop())

	// Make sure we get an error retrieving transactions on stopped persister.
	_, err = mempoolPersister.RetrieveTransactions()
	require.Contains(err.Error(), MempoolErrorNotRunning.Error())

	// Reopen the db.
	require.NoError(db.Close())
	require.NoError(db.Setup())

	// Restart the mempool persister.
	mempoolPersister.Start()

	// Make sure we can retrieve the transactions again.
	retrievedTxns, err = mempoolPersister.RetrieveTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	require.NoError(db.Close())
	require.NoError(db.Erase())
}

func waitForPersisterToProcessEventQueue(mempoolPersister *MempoolPersister) {
	mempoolPersister.Lock()
	for len(mempoolPersister.eventQueue) > 0 || len(mempoolPersister.updateBatch) > 0 {
		mempoolPersister.Unlock()
		time.Sleep(100 * time.Millisecond)
		mempoolPersister.Lock()
	}
	mempoolPersister.Unlock()
}
