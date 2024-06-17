package lib

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v3"
	"github.com/stretchr/testify/require"
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

	opts := DefaultBadgerOptions(dir)
	db, err := badger.Open(opts)
	require.NoError(err)
	defer os.RemoveAll(dir)
	defer db.Close()

	mempoolPersister := NewMempoolPersister(db, 100)

	// Start the mempool persister.
	mempoolPersister.Start()
	require.True(mempoolPersister.IsRunning())

	// Add all the transactions to the mempool.
	for _, txn := range txnPool {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		mempoolPersister.EnqueueEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err := mempoolPersister.GetPersistedTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Add the same transactions again and ensure there are no overlaps.
	for ii := 0; ii < addRemoveCases; ii++ {
		event := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventAdd,
		}
		mempoolPersister.EnqueueEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err = mempoolPersister.GetPersistedTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Remove couple transactions from the mempool
	for ii := 0; ii < addRemoveCases; ii++ {
		event := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventRemove,
		}
		mempoolPersister.EnqueueEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err = mempoolPersister.GetPersistedTransactions()
	require.NoError(err)
	require.Equal(len(txnPool)-addRemoveCases, len(retrievedTxns))

	// Add & Remove some transactions again and ensure transactions were really removed.
	for ii := 0; ii < addRemoveCases; ii++ {
		event := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventAdd,
		}
		mempoolPersister.EnqueueEvent(event)

		event2 := &MempoolEvent{
			Txn:  txnPool[ii],
			Type: MempoolEventRemove,
		}
		mempoolPersister.EnqueueEvent(event2)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err = mempoolPersister.GetPersistedTransactions()
	require.NoError(err)
	require.Equal(len(txnPool)-addRemoveCases, len(retrievedTxns))

	require.NoError(mempoolPersister.Stop())
	require.False(mempoolPersister.IsRunning())
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

	opts := DefaultBadgerOptions(dir)
	db, err := badger.Open(opts)
	require.NoError(err)

	mempoolPersister := NewMempoolPersister(db, 100)

	// Start the mempool persister.
	mempoolPersister.Start()
	require.True(mempoolPersister.IsRunning())

	// Add all the transactions to the mempool.
	for _, txn := range txnPool {
		event := &MempoolEvent{
			Txn:  txn,
			Type: MempoolEventAdd,
		}
		mempoolPersister.EnqueueEvent(event)
	}

	waitForPersisterToProcessEventQueue(mempoolPersister)
	retrievedTxns, err := mempoolPersister.GetPersistedTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Stop the mempool persister.
	require.NoError(mempoolPersister.Stop())
	require.False(mempoolPersister.IsRunning())

	// Make sure we get an error retrieving transactions on stopped persister.
	_, err = mempoolPersister.GetPersistedTransactions()
	require.Contains(err.Error(), MempoolErrorNotRunning.Error())

	// Reopen the db.
	require.NoError(db.Close())
	db, err = badger.Open(opts)
	require.NoError(err)
	mempoolPersister = NewMempoolPersister(db, 100)

	// Restart the mempool persister.
	mempoolPersister.Start()
	require.True(mempoolPersister.IsRunning())

	// Make sure we can retrieve the transactions again.
	retrievedTxns, err = mempoolPersister.GetPersistedTransactions()
	require.NoError(err)
	require.Equal(len(txnPool), len(retrievedTxns))

	// Stop the mempool persister.
	require.NoError(mempoolPersister.Stop())
	require.False(mempoolPersister.IsRunning())

	require.NoError(db.Close())
	require.NoError(os.RemoveAll(dir))
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
