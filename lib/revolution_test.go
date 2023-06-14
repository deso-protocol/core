package lib

import (
	"github.com/stretchr/testify/require"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestFeeTimeBucket(t *testing.T) {
	seed := int64(1)
	testCases := 10000
	maxFee := uint64(10000)
	maxTimestamp := uint64(100)

	require := require.New(t)
	rand := rand.New(rand.NewSource(seed))
	txnPool := []*MempoolTx{}
	for ii := 0; ii < testCases; ii++ {
		txnPool = append(txnPool, &MempoolTx{
			FeePerKB: rand.Uint64()%maxFee + 1000,
			Added:    time.UnixMicro(int64(rand.Uint64() % maxTimestamp)),
			Hash:     NewBlockHash(RandomBytes(32)),
		})
	}

	// Create new TransactionRegister and add the txn pool
	txnRegister := NewTransactionRegister(&DeSoTestnetParams, nil)
	for ii := 0; ii < testCases; ii++ {
		require.Equal(true, txnRegister.AddTransaction(txnPool[ii]))
	}

	// Iterate through TransactionRegister to get Fee-Time ordering.
	registerTxns := txnRegister.GetFeeTimeTransactions()

	// Now sort the txnPool by Fee-Time without priority queues.
	sort.Slice(txnPool, func(i, j int) bool {
		feeBucketI := MapFeeToNthBucket(txnPool[i].FeePerKB, nil)
		feeBucketJ := MapFeeToNthBucket(txnPool[j].FeePerKB, nil)
		if feeBucketI > feeBucketJ {
			return true
		} else if feeBucketI == feeBucketJ {
			if txnPool[i].Added.UnixNano() < txnPool[j].Added.UnixNano() {
				return true
			} else if txnPool[i].Added.UnixNano() == txnPool[j].Added.UnixNano() {
				if txnPool[i].FeePerKB > txnPool[j].FeePerKB {
					return true
				} else if txnPool[i].FeePerKB == txnPool[j].FeePerKB {
					if txnPool[i].Hash == nil || txnPool[j].Hash == nil {
						return true
					}
					return txnPool[i].Hash.String() > txnPool[j].Hash.String()
				}
			}
		}
		return false
	})
	//glog.Infof("===== sorted txn pool =====")

	// Now compare the priority queue ordering with the non-priority queue ordering.
	require.Equal(len(registerTxns), len(txnPool))
	for ii := 0; ii < len(txnPool); ii++ {
		//glog.Infof("Fee (%v) Timestamp (%v) | Fee (%v) Timestamp (%v)", txnPool[ii].FeePerKB, txnPool[ii].Added.UnixNano(),
		//	registerTxns[ii].FeePerKB, registerTxns[ii].Added.UnixNano())
		require.Equal(registerTxns[ii].FeePerKB, txnPool[ii].FeePerKB)
		require.Equal(registerTxns[ii].Added.UnixNano(), txnPool[ii].Added.UnixNano())
	}
}

func TestComputeFeeBucket(t *testing.T) {
	require := require.New(t)
	_ = require

	feeBuckets := []uint64{}
	for ii := 0; ii < 100; ii++ {
		feeBuckets = append(feeBuckets, ComputeNthFeeBucket(ii, nil))
	}

	for ii := 0; ii < 100; ii++ {
		require.Equal(feeBuckets[ii], ComputeNthFeeBucket(ii, nil))
	}
}

func TestComputeFeeBucketWithFee(t *testing.T) {
	verifyFeeBucket := func(n int, fee uint64) bool {
		bucket := ComputeNthFeeBucket(n, nil)
		if bucket > fee {
			return false
		}
		if bucket < fee && ComputeNthFeeBucket(n+1, nil) <= fee {
			return false
		}
		return true
	}

	require := require.New(t)
	_ = require
	for ii := uint64(1000); ii < 100000; ii++ {
		n := MapFeeToNthBucket(ii, nil)
		require.True(verifyFeeBucket(n, ii))
	}
}
