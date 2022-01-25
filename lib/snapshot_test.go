package lib

import (
	"encoding/hex"
	"fmt"
	"github.com/NVIDIA/sortedmap"
	"github.com/cloudflare/circl/group"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/dgraph-io/badger/v3"
	"github.com/oleiade/lane"
	"github.com/stretchr/testify/require"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestDeque(t *testing.T) {
	require := require.New(t)
	_ = require

	deque := lane.NewDeque()
	fmt.Println(deque.Capacity(), deque.Empty())
	for ii := 0; ii < 5; ii ++ {
		fmt.Println(deque.Append(ii))
	}

	lastElem := make(map[int]int)
	lastElem[1] = 5
	lastElem[3] = 2
	deque.Append(lastElem)
	fmt.Println(deque.Capacity(), deque.Empty())

	fmt.Println(deque.Shift())
	fmt.Println(deque.Last())
	lastElem[5] = 122
	fmt.Println(deque.Last())
	vv := deque.Last().(map[int]int)
	vv[17] = 444
	fmt.Println(deque.Last())
}

func TestBadgerConcurrentWrite(t *testing.T) {
	require := require.New(t)
	_ = require

	db, _ := GetTestBadgerDb()
	const keySize = 16
	const valSize = 32
	sequentialWrites := 128
	concurrentWrites := 512

	var keys [][keySize]byte
	var vals [][valSize]byte
	for ii := 0; ii < sequentialWrites + concurrentWrites; ii++ {
		var key [keySize]byte
		var val [valSize]byte
		copy(key[:], RandomBytes(keySize))
		copy(val[:], RandomBytes(valSize))
		keys = append(keys, key)
		vals = append(vals, val)
	}

	wait := sync.WaitGroup{}
	wait.Add(1)

	err := db.Update(func(txn *badger.Txn) error {
		for ii := 0; ii < sequentialWrites; ii++ {
			err := txn.Set(keys[ii][:], vals[ii][:])
			if err != nil {
				return err
			}
		}

		// This won't work because of concurrency
		//go func(txn *badger.Txn, wait *sync.WaitGroup) {
		//	for jj := sequentialWrites; jj < sequentialWrites + concurrentWrites; jj++ {
		//		_ = txn.Set(keys[jj][:], vals[jj][:])
		//	}
		//	wait.Done()
		//}(txn, &wait)

		go func(db *badger.DB, wait *sync.WaitGroup) {
			err := db.Update(func(txn *badger.Txn) error {
				for jj := sequentialWrites; jj < sequentialWrites + concurrentWrites; jj++ {
					err := txn.Set(keys[jj][:], vals[jj][:])
					if err != nil {
						fmt.Printf("Error in concurrent write: %v", err)
						return err
					}
				}
				return nil
			})
			if err != nil {
				fmt.Printf("Error, failed to write concurrently: %v", err)
			}
			fmt.Println("Finished concurrent write")
			wait.Done()
		}(db, &wait)
		return nil
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Println("Finished sequential write")

	wait.Wait()
	fmt.Println("Finished everything")

	err = db.View(func(txn *badger.Txn) error {
		for ii := 0; ii < sequentialWrites + concurrentWrites; ii++ {
			item, err := txn.Get(keys[ii][:])
			if err != nil {
				fmt.Printf("Error: %v, at index %v\n", err, ii)
				return err
			}
			value, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			require.Equal(reflect.DeepEqual(hex.EncodeToString(value), hex.EncodeToString(vals[ii][:])), true)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	fmt.Println("Finished comparison")
}

func TestBadgerEmptyWrite(t *testing.T) {
	require := require.New(t)

	db, _ := GetTestBadgerDb()
	key := []byte{1, 2, 3}
	val := []byte{}

	err := db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, val)
	})
	require.NoError(err)

	var readVal []byte
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		readVal, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return nil
	})
	require.NoError(err)

	fmt.Println(readVal, val)
	require.Equal(reflect.DeepEqual(hex.EncodeToString(val), hex.EncodeToString(readVal)), true)
}

// Part of the process of maintaining state snapshot involves writing
// to so-called Ancestral Records after a DB flush in utxo_view.
// To optimize the process, we will write to BadgerDB with ordered
// (key, value) pairs, which should theoretically be faster considering
// Badger's LSM tree design. In this test we benchmark the data structure
// that would store the (k,v) pairs.
// 1. A sorted map based on Left-leaning red-black trees.
// 2. A naive approach with a map and a sorted list of keys.
// Result:
// LLRB is about 2x slower than the map approach, but don't require
// storing 2x keys, which could be useful when utxo_view becomes large.
func TestSortedMap(t *testing.T) {
	LLRB := sortedmap.NewLLRBTree(sortedmap.CompareString, nil)

	nodup := make(map[string]bool)
	size := 1000000
	keySize := int32(32)
	valueSize := int32(256)

	var kList, vList []string
	for ii:=0; ii<size; ii++{
		key := hex.EncodeToString(RandomBytes(keySize))
		if _, ok := nodup[key]; ok {
			continue
		}
		value := hex.EncodeToString(RandomBytes(valueSize))
		kList = append(kList, key)
		vList = append(vList, value)
		nodup[key] = true
	}

	fmt.Printf("Total number of (k,v) pairs to add: %v\n", len(nodup))
	fmt.Println("--------------")

	timeLLRBAddKeys := 0.0

	for ii := 0; ii < len(kList); ii++ {
		k, v := kList[ii], vList[ii]
		timeStart := time.Now()
		ok, err := LLRB.Put(k, v)
		timeLLRBAddKeys += (time.Since(timeStart)).Seconds()
		require.NoError(t, err)
		require.Equal(t, ok, true)
	}
	fmt.Printf("Total time to add keys to LLRB %v\n", timeLLRBAddKeys)

	timeSMapAddKeys := 0.0
	SMap := make(map[string]string)
	SKList := make([]string, 0)
	for ii := 0; ii < len(kList); ii++ {
		k, v := kList[ii], vList[ii]
		timeStart := time.Now()
		SMap[k] = v
		SKList = append(SKList, k)
		timeSMapAddKeys += (time.Since(timeStart)).Seconds()
	}
	timeStart := time.Now()
	sort.Strings(SKList)
	timeSMapAddKeys += (time.Since(timeStart)).Seconds()
	fmt.Printf("Total time to add and sort keys in a map %v\n", timeSMapAddKeys)

	prevKey := hex.EncodeToString([]byte{0})
	timeLLRBGetKeys := 0.0
	timeSMapGetKeys := 0.0
	for i := 0; i < len(kList); i++ {
		timeStart = time.Now()
		kLLRB, vLLRB, ok, err := LLRB.GetByIndex(i)
		timeLLRBGetKeys += (time.Since(timeStart)).Seconds()
		require.NoError(t, err)
		require.Equal(t, ok, true)
		require.Greater(t, kLLRB.(string), prevKey)
		prevKey = kLLRB.(string)

		timeStart = time.Now()
		kSMap, vSMap := SKList[i], SMap[SKList[i]]
		timeSMapGetKeys += (time.Since(timeStart)).Seconds()
		require.Equal(t, kLLRB, kSMap)
		require.Equal(t, vLLRB, vSMap)
		//fmt.Printf("key: %v, value %v\n", k, v)
	}

	fmt.Println("--------------")
	fmt.Printf("Total time to fetch keys in LLRB %v\n", timeLLRBGetKeys)
	fmt.Printf("Total time to fetch keys in Sorted Map %v\n", timeSMapGetKeys)
	fmt.Println("--------------")
	fmt.Printf("Total time to add and fetch keys in LLRB %v\n", timeLLRBAddKeys + timeLLRBGetKeys)
	fmt.Printf("Total time to add and fetch keys in Sorted Map %v\n", timeSMapAddKeys + timeSMapGetKeys)
}

func TestStateChecksumBasicAddRemove(t *testing.T) {
	require := require.New(t)
	_ = require

	z := StateChecksum{}
	z.Initialize()
	identity := group.Ristretto255.Identity()
	bytesA := []byte("This is a test data")
	bytesB := []byte("This is another test")
	bytesC := []byte("This is yet another test")

	// Basic check #1
	// Compute checksum A + B, then remove B from the checksum and confirm it's equal to A
	var check1, check2, check3 group.Element
	check1 = group.Ristretto255.NewElement()
	check2 = group.Ristretto255.NewElement()
	check3 = group.Ristretto255.NewElement()
	z.AddBytes(bytesA)
	check1Bytes, _ := z.Checksum.MarshalBinary()
 	_ = check1.UnmarshalBinary(check1Bytes)
	z.AddBytes(bytesB)
 	check2Bytes, _ := z.Checksum.MarshalBinary()
	_ = check2.UnmarshalBinary(check2Bytes)
	z.RemoveBytes(bytesB)
	require.Equal(z.Checksum.IsEqual(check1), true)
	z.RemoveBytes(bytesA)
	require.Equal(z.Checksum.IsEqual(identity), true)

	// Basic check #2
	// Check if checksum A + B is equal to checksum B + A
	z.AddBytes(bytesB)
	z.AddBytes(bytesA)
	require.Equal(check2.IsEqual(z.Checksum), true)
	z.RemoveBytes(bytesA)
	z.RemoveBytes(bytesB)
	require.Equal(z.Checksum.IsEqual(identity), true)

	// Basic check #3
	// Check if checksum A + B + C is the same as C + A + B and B + A + C
	// Do some random removes to make sure everything is commutative.
	// A + B + C
	z.AddBytes(bytesA)
	z.AddBytes(bytesB)
	z.AddBytes(bytesC)
	check1Bytes, _ = z.Checksum.MarshalBinary()
	_ = check1.UnmarshalBinary(check1Bytes)
	// Remove C, A, B
	z.RemoveBytes(bytesC)
	z.RemoveBytes(bytesA)
	z.RemoveBytes(bytesB)
	require.Equal(z.Checksum.IsEqual(identity), true)

	// C + A + B
	z.AddBytes(bytesC)
	z.AddBytes(bytesA)
	z.AddBytes(bytesB)
	check2Bytes, _ = z.Checksum.MarshalBinary()
	_ = check2.UnmarshalBinary(check2Bytes)
	// Remove A, B, C
	z.RemoveBytes(bytesA)
	z.RemoveBytes(bytesB)
	z.RemoveBytes(bytesC)
	require.Equal(z.Checksum.IsEqual(identity), true)

	// Add B + A + C
	z.AddBytes(bytesB)
	z.AddBytes(bytesA)
	z.AddBytes(bytesC)
	check3Bytes, _ := z.Checksum.MarshalBinary()
	_ = check3.UnmarshalBinary(check3Bytes)
	require.Equal(check2.IsEqual(check1), true)
	require.Equal(check3.IsEqual(check1), true)
	z.RemoveBytes(bytesB)
	z.RemoveBytes(bytesA)
	z.RemoveBytes(bytesC)
	require.Equal(z.Checksum.IsEqual(identity), true)
}

func TestStateChecksumBirthdayParadox(t *testing.T) {
	require := require.New(t)
	_ = require

	z := StateChecksum{}
	z.Initialize()

	iterationNumber := 1
	testNumber := 1000000

	// We will test adding / removing a bunch of data to the state checksum and verify
	// that the final checksum is identical regardless of the order of operation.
	seed := []byte("random-salt")
	hashes := [][]byte{}
	for ii := uint64(0); ii < uint64(testNumber); ii++ {
		seedTemp := append(seed, UintToBuf(ii)...)
		hash := []byte{}
		hash = append(hash, merkletree.Sha256DoubleHash(seedTemp)...)
		hashes = append(hashes, hash)
	}
	for jj := 0; jj < testNumber; jj++ {
		z.AddBytes(hashes[jj])
	}
	var val group.Element
	val = group.Ristretto255.NewElement()
	valBytes, _ := z.Checksum.MarshalBinary()
	_ = val.UnmarshalBinary(valBytes)
	for jj := 0; jj < testNumber; jj++ {
		z.RemoveBytes(hashes[jj])
	}

	// Build a list of indexes so we can reorder the hashes when we add / remove them.
	indexes := []int{}
	for ii := 0; ii < testNumber; ii++ {
		indexes = append(indexes, ii)
	}
	rand.Shuffle(len(indexes), func(i, j int) {
		indexes[i], indexes[j] = indexes[j], indexes[i]
	})

	//fmt.Println(indexes)
	repetitions := make(map[string]bool)
	// Test the adding / removing of the hashes iteration number of times.
	// Time how much time it took us to compute all the checksum operations.
	totalElappsed := 0.0
	for ii := 0; ii < iterationNumber; ii++ {
		rand.Shuffle(len(indexes), func(i, j int) {
			indexes[i], indexes[j] = indexes[j], indexes[i]
		})
		timeStart := time.Now()
		for jj := 0; jj < testNumber; jj++ {
			z.AddBytes(hashes[jj])
			checksumBytes, _ := z.Checksum.MarshalBinary()
			checksumString := string(checksumBytes)
			if _, exists := repetitions[checksumString]; exists {
				t.Fatalf("Found birthday paradox solution! (%v)", checksumBytes)
			}
			repetitions[checksumString] = true
		}
		require.Equal(z.Checksum.IsEqual(val), true)
		for jj := 0; jj < testNumber; jj++ {
			z.RemoveBytes(hashes[jj])
		}
		totalElappsed += (time.Since(timeStart)).Seconds()
	}
	fmt.Println(totalElappsed)
}
