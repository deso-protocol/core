package lib

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/NVIDIA/sortedmap"
	"github.com/btcsuite/btcd/btcec"
	"github.com/cloudflare/circl/group"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/dgraph-io/badger/v3"
	"github.com/oleiade/lane"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"math"
	"math/rand"
	"reflect"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"
)

type enhancedHeader struct {
	// Note this is encoded as a fixed-width uint32 rather than a
	// uvarint or a uint64.
	Version uint32

	// Hash of the previous block in the chain.
	PrevBlockHash *BlockHash

	// The merkle root of all the transactions contained within the block.
	TransactionMerkleRoot *BlockHash

	// The unix timestamp (in seconds) specifying when this block was
	// mined.
	TstampSecs uint64

	// The height of the block this header corresponds to.
	Height uint64

	// The nonce that is used by miners in order to produce valid blocks.
	//
	// Note: Before the upgrade from HeaderVersion0 to HeaderVersion1, miners would make
	// use of ExtraData in the BlockRewardMetadata to get extra nonces. However, this is
	// no longer needed since HeaderVersion1 upgraded the nonce to 64 bits from 32 bits.
	Nonce uint64

	// An extra nonce that can be used to provice *even more* entropy for miners, in the
	// event that ASICs become powerful enough to have birthday problems in the future.
	ExtraNonce uint64
}

func (msg *enhancedHeader) ToBytes(preSignature bool) ([]byte, error) {
	retBytes := []byte{}

	// Version
	{
		scratchBytes := [4]byte{}
		binary.BigEndian.PutUint32(scratchBytes[:], msg.Version)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// PrevBlockHash
	prevBlockHash := msg.PrevBlockHash
	if prevBlockHash == nil {
		prevBlockHash = &BlockHash{}
	}
	retBytes = append(retBytes, prevBlockHash[:]...)

	// TransactionMerkleRoot
	transactionMerkleRoot := msg.TransactionMerkleRoot
	if transactionMerkleRoot == nil {
		transactionMerkleRoot = &BlockHash{}
	}
	retBytes = append(retBytes, transactionMerkleRoot[:]...)

	// TstampSecs
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.TstampSecs)
		retBytes = append(retBytes, scratchBytes[:]...)

		// TODO: Don't allow this field to exceed 32-bits for now. This will
		// adjust once other parts of the code are fixed to handle the wider
		// type.
		if msg.TstampSecs > math.MaxUint32 {
			return nil, fmt.Errorf("EncodeHeaderVersion1: TstampSecs not yet allowed " +
				"to exceed max uint32. This will be fixed in the future")
		}
	}

	// Height
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.Height)
		retBytes = append(retBytes, scratchBytes[:]...)

		// TODO: Don't allow this field to exceed 32-bits for now. This will
		// adjust once other parts of the code are fixed to handle the wider
		// type.
		if msg.Height > math.MaxUint32 {
			return nil, fmt.Errorf("EncodeHeaderVersion1: Height not yet allowed " +
				"to exceed max uint32. This will be fixed in the future")
		}
	}

	// Nonce
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.Nonce)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	// ExtraNonce
	{
		scratchBytes := [8]byte{}
		binary.BigEndian.PutUint64(scratchBytes[:], msg.ExtraNonce)
		retBytes = append(retBytes, scratchBytes[:]...)
	}

	return retBytes, nil
}

func TestTypes(t *testing.T) {
	r := Prefixes
	fmt.Println(r)

	fmt.Println(Prefixes.PrefixBlockHashToBlock)
	v := reflect.ValueOf(*r)
	fmt.Println("ITERATING OVER ALL FIELDS")
	for i := 0; i < v.NumField(); i++ {
		fmt.Println("PREFIX:", v.Field(i).Interface())
	}
}

func TestTest(t *testing.T) {
	x := []byte{12, 2, 0, 108, 239, 24, 210, 138, 192, 54, 137, 45, 95, 211, 118, 6, 107, 69, 186, 232, 8, 118, 195, 156, 103, 24, 3, 28, 229, 36, 45, 196, 140, 236, 22, 184, 103, 240, 80, 87, 123, 74}
	fmt.Println(hex.EncodeToString(x))
}

func TestFromBytes(t *testing.T) {
	require := require.New(t)
	_ = require

	priv, err := btcec.NewPrivateKey(btcec.S256())
	require.NoError(err)
	expectedBlock.BlockProducerInfo.Signature, err = priv.Sign([]byte{0x01, 0x02, 0x03})
	require.NoError(err)

	bytesExpectedBlock, err := expectedBlock.ToBytes(false)
	require.NoError(err)

	testBlock := NewMessage(MsgTypeBlock).(*MsgDeSoBlock)
	err = testBlock.FromBytes(bytesExpectedBlock)
	require.NoError(err)

	require.Equal(*testBlock, *expectedBlock)

	expectedHeader := &MsgDeSoHeader{
		Version: 1,
		PrevBlockHash: &BlockHash{
			0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11,
			0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21,
			0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x30, 0x31,
			0x32, 0x33,
		},
		TransactionMerkleRoot: &BlockHash{
			0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53,
			0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63,
			0x64, 0x65,
		},
		TstampSecs: uint64(0x70717273),
		Height:     uint64(99999),
		Nonce:      uint64(123456),
	}

	enhancedHeader := &enhancedHeader{
		Version:       expectedHeader.Version,
		PrevBlockHash: expectedHeader.PrevBlockHash,
		TransactionMerkleRoot: &BlockHash{
			0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43,
			0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x50, 0x51, 0x52, 0x53,
			0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x60, 0x61, 0x62, 0x63,
			0x64, 0x65,
		},
		TstampSecs: expectedHeader.TstampSecs,
		Height:     expectedHeader.Height,
		Nonce:      expectedHeader.Nonce,
	}

	expectedHeaderBytes, err := expectedHeader.ToBytes(false)
	enhancedHeaderBytes, err := enhancedHeader.ToBytes(false)
	testHeader := NewMessage(MsgTypeHeader).(*MsgDeSoHeader)
	err = testHeader.FromBytes(enhancedHeaderBytes)
	require.NoError(err)
	testHeaderBytes, err := testHeader.ToBytes(false)
	require.NoError(err)
	fmt.Println(expectedHeaderBytes)
	fmt.Println(testHeaderBytes)
}

func TestDeque(t *testing.T) {
	require := require.New(t)
	_ = require

	deque := lane.NewDeque()
	fmt.Println(deque.Capacity(), deque.Empty())
	for ii := 0; ii < 5; ii++ {
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

	lastArray := make([]byte, 0)
	lastArray = append(lastArray, 5)
	lastArray = append(lastArray, 7)
	deque.Append(lastArray)
	lastArray = append(lastArray, 9)

	fmt.Println(lastArray)
	fmt.Println(deque.Last())

	type x struct {
		arr []byte
	}
	tester := &x{
		arr: make([]byte, 0),
	}
	tester.arr = append(tester.arr, 8)
	tester.arr = append(tester.arr, 20)
	fmt.Println("tester", tester)
	deque.Append(tester)
	tester.arr = append(tester.arr, 11)
	fmt.Println("deque.Last()", deque.Last())
	zz := deque.Last().(*x)
	zz.arr = append(zz.arr, 18)
	fmt.Println("deque.Last()", deque.Last())
	fmt.Println("tester", tester)
}

func TestChannelThingy(t *testing.T) {
	testChan := make(chan int, 10)

	delay := func(ii int) {
		fmt.Println("Got in, chanel len is:", len(testChan), "and ii is:", ii)
		time.Sleep(time.Second)
	}

	fmt.Println(len(testChan))
	bytesTest := []byte{9, 1, 8, 8, 0, 0, 0, 0, 0, 0, 1, 226}
	snap := Snapshot{}
	fmt.Println(snap.isState(bytesTest))

	testChan <- 1
	testChan <- 2
	testChan <- 3

	go func() {
		for {
			if len(testChan) > 0 {
				continue
			} else {
				break
			}
		}
		fmt.Println("Got out!")
	}()

out:
	for {
		ii := <-testChan
		delay(ii)
		if ii == 3 {
			break out
		}
	}
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
	for ii := 0; ii < sequentialWrites+concurrentWrites; ii++ {
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
				for jj := sequentialWrites; jj < sequentialWrites+concurrentWrites; jj++ {
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
		for ii := 0; ii < sequentialWrites+concurrentWrites; ii++ {
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
// to so-called Ancestral Records after a DB flush in UtxoView.
// To optimize the process, we will write to BadgerDB with ordered
// (key, value) pairs, which should theoretically be faster considering
// Badger's LSM tree design. In this test we benchmark the data structure
// that would store the (k,v) pairs.
// 1. A sorted map based on Left-leaning red-black trees.
// 2. A naive approach with a map and a sorted list of keys.
// Result:
// LLRB is about 2x slower than the map approach, but don't require
// storing 2x keys, which could be useful when UtxoView becomes large.
func TestSortedMap(t *testing.T) {
	LLRB := sortedmap.NewLLRBTree(sortedmap.CompareString, nil)

	nodup := make(map[string]bool)
	size := 1000000
	keySize := int32(32)
	valueSize := int32(256)

	var kList, vList []string
	for ii := 0; ii < size; ii++ {
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
	fmt.Printf("Total time to add and fetch keys in LLRB %v\n", timeLLRBAddKeys+timeLLRBGetKeys)
	fmt.Printf("Total time to add and fetch keys in Sorted Map %v\n", timeSMapAddKeys+timeSMapGetKeys)
}

func TestStateChecksumBasicAddRemove(t *testing.T) {
	require := require.New(t)
	_ = require

	z := StateChecksum{}
	z.Initialize(nil, nil)
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
	require.NoError(z.AddBytes(bytesA))
	check1Bytes, err := z.ToBytes()
	vv, err := z.GetChecksum()
	check1.Add(group.Ristretto255.Identity(), vv)
	fmt.Println("check1", check1)
	require.NoError(err)
	//err = check1.UnmarshalBinary(check1Bytes)
	require.NoError(err)
	fmt.Println("check1", check1)
	require.NoError(z.AddBytes(bytesB))
	fmt.Println("check1", check1)
	fmt.Println(z.GetChecksum())
	check2Bytes, err := z.ToBytes()
	require.NoError(err)
	err = check2.UnmarshalBinary(check2Bytes)
	require.NoError(err)
	require.NoError(z.RemoveBytes(bytesB))

	checksum, err := z.GetChecksum()
	require.NoError(err)
	fmt.Println("check1", check1)
	fmt.Println("checksum", checksum)
	require.Equal(checksum.IsEqual(check1), true)
	require.NoError(z.RemoveBytes(bytesA))
	checksum, err = z.GetChecksum()
	require.NoError(err)
	require.Equal(checksum.IsEqual(identity), true)

	// Basic check #2
	// Check if checksum A + B is equal to checksum B + A
	require.NoError(z.AddBytes(bytesB))
	require.NoError(z.AddBytes(bytesA))
	checksum, err = z.GetChecksum()
	require.NoError(err)
	require.Equal(check2.IsEqual(checksum), true)
	require.NoError(z.RemoveBytes(bytesA))
	require.NoError(z.RemoveBytes(bytesB))
	checksum, err = z.GetChecksum()
	require.NoError(err)
	require.Equal(checksum.IsEqual(identity), true)

	// Basic check #3
	// Check if checksum A + B + C is the same as C + A + B and B + A + C
	// Do some random removes to make sure everything is commutative.
	// A + B + C
	require.NoError(z.AddBytes(bytesA))
	require.NoError(z.AddBytes(bytesB))
	require.NoError(z.AddBytes(bytesC))
	check1Bytes, err = z.ToBytes()
	require.NoError(err)
	err = check1.UnmarshalBinary(check1Bytes)
	require.NoError(err)
	// Remove C, A, B
	require.NoError(z.RemoveBytes(bytesC))
	require.NoError(z.RemoveBytes(bytesA))
	require.NoError(z.RemoveBytes(bytesB))
	checksum, err = z.GetChecksum()
	require.NoError(err)
	require.Equal(checksum.IsEqual(identity), true)

	// C + A + B
	require.NoError(z.AddBytes(bytesC))
	require.NoError(z.AddBytes(bytesA))
	require.NoError(z.AddBytes(bytesB))
	check2Bytes, err = z.ToBytes()
	require.NoError(err)
	err = check2.UnmarshalBinary(check2Bytes)
	require.NoError(err)
	// Remove A, B, C
	require.NoError(z.RemoveBytes(bytesA))
	require.NoError(z.RemoveBytes(bytesB))
	require.NoError(z.RemoveBytes(bytesC))
	checksum, err = z.GetChecksum()
	require.NoError(err)
	require.Equal(checksum.IsEqual(identity), true)

	// Add B + A + C
	require.NoError(z.AddBytes(bytesB))
	require.NoError(z.AddBytes(bytesA))
	require.NoError(z.AddBytes(bytesC))
	check3Bytes, err := z.ToBytes()
	require.NoError(err)
	err = check3.UnmarshalBinary(check3Bytes)
	require.NoError(err)
	require.Equal(check2.IsEqual(check1), true)
	require.Equal(check3.IsEqual(check1), true)
	require.NoError(z.RemoveBytes(bytesB))
	require.NoError(z.RemoveBytes(bytesA))
	require.NoError(z.RemoveBytes(bytesC))
	checksum, err = z.GetChecksum()
	require.NoError(err)
	require.Equal(checksum.IsEqual(identity), true)
}

func TestFasterHashToCurve(t *testing.T) {
	//require := require.New(t)

	//p1 := group.Ristretto255.Identity()
	//p2 := group.Ristretto255.Identity()
	seedString := []byte("random byte string4")
	//bytes2 := []byte("random byte string2")
	dst := []byte("random-dst")

	fmt.Println(int(float64(runtime.GOMAXPROCS(0))))
	maxWorkers := runtime.GOMAXPROCS(0)
	sem := semaphore.NewWeighted(int64(maxWorkers))
	ctx := context.TODO()
	//if err := sem.Acquire(ctx, 5); err != nil {
	//	fmt.Printf("Failed to acquire the semaphore: (%v)\n", err)
	//}
	//go func() {
	//	time.Sleep(2*time.Second)
	//	sem.Release(5)
	//	fmt.Println("Finished the wait")
	//}()
	//fmt.Println("Waiting sir")
	//if err := sem.Acquire(ctx, int64(maxWorkers)); err != nil {
	//	fmt.Printf("Failed to acquire the semaphore: (%v)\n", err)
	//}
	//fmt.Println("Acquired sir")
	//sem.Release(int64(maxWorkers))

	testCounter := uint64(1 << 19)
	var muter sync.Mutex
	for ii := uint64(0); ii < testCounter; ii++ {
		if err := sem.Acquire(ctx, 1); err != nil {
			fmt.Printf("Failed to acquire the semaphore: (%v)\n", err)
		}
		go func(jj uint64) {
			defer sem.Release(1)
			bytes := append(seedString, EncodeUint64(jj)...)
			elem := group.Ristretto255.HashToElement(bytes, dst)
			muter.Lock()
			elem.Add(elem, elem)
			muter.Unlock()
			//fmt.Println(elem.MarshalBinaryCompress())
		}(ii)
	}
	if err := sem.Acquire(ctx, int64(maxWorkers)); err != nil {
		fmt.Println("FAILED")
	}
	fmt.Println("YEAAAH")
}

func TestStateChecksumBirthdayParadox(t *testing.T) {
	require := require.New(t)
	_ = require

	z := StateChecksum{}
	z.Initialize(nil, nil)

	iterationNumber := 1
	testNumber := 1000

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
		require.NoError(z.AddBytes(hashes[jj]))
	}
	var val group.Element
	val = group.Ristretto255.NewElement()
	valBytes, err := z.ToBytes()
	require.NoError(err)
	_ = val.UnmarshalBinary(valBytes)
	for jj := 0; jj < testNumber; jj++ {
		require.NoError(z.RemoveBytes(hashes[jj]))
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
			require.NoError(z.AddBytes(hashes[jj]))
			checksumBytes, err := z.ToBytes()
			require.NoError(err)
			checksumString := string(checksumBytes)
			if _, exists := repetitions[checksumString]; exists {
				t.Fatalf("Found birthday paradox solution! (%v)", checksumBytes)
			}
			repetitions[checksumString] = true
		}
		checksum, err := z.GetChecksum()
		require.NoError(err)
		require.Equal(checksum.IsEqual(val), true)
		for jj := 0; jj < testNumber; jj++ {
			require.NoError(z.RemoveBytes(hashes[jj]))
		}
		totalElappsed += (time.Since(timeStart)).Seconds()
	}
	fmt.Println(totalElappsed)
}
