package lib

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/group"
	merkletree "github.com/deso-protocol/go-merkle-tree"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
	"math"
	"math/rand"
	"runtime"
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

func TestStateChecksumBasicAddRemove(t *testing.T) {
	require := require.New(t)
	_ = require

	// Initialize the checksum.
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
