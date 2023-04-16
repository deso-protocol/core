package encoding

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"compress/zlib"
	"github.com/golang/snappy"
	"github.com/klauspost/compress/s2"
	"github.com/stretchr/testify/require"
	"math/rand"
	"sort"
	"testing"
	"time"
)

func TestSimpleCompression(t *testing.T) {
	require := require.New(t)

	// Compress a sample list
	sampleList := []uint64{5, 7, 11, 28, 35}
	ef := NewEFEncoder(sampleList)
	compressedListBytes := ef.ToBytes()

	// Recover list from bytes
	efCopy := EFEncoder{}
	err := efCopy.FromBytes(bytes.NewReader(compressedListBytes))
	require.NoError(err)

	// Verify that the recovered list matches the original.
	recoveredList, err := efCopy.GetSequence()
	require.NoError(err)
	require.Equal(true, compareSequences(sampleList, recoveredList))

}

func compareSequences(x, y []uint64) bool {
	if len(x) != len(y) {
		return false
	}
	for ii, xVal := range x {
		if y[ii] != xVal {
			return false
		}
	}
	return true
}

func generateFixedRangeSequence(rand *rand.Rand, length uint64, maxRange uint64, maxUpperBound uint64) (
	_lowerBound uint64, _sequence []uint64) {
	sequence := make([]uint64, length)
	lowerBound := rand.Uint64() % (maxUpperBound - maxRange + 1)
	for i := range sequence {
		sequence[i] = (rand.Uint64() % maxRange) + lowerBound
	}
	sort.Slice(sequence, func(ii, jj int) bool {
		return sequence[ii] < sequence[jj]
	})
	return lowerBound, sequence
}

func TestCompressionBenchmark(t *testing.T) {
	require := require.New(t)

	rand := rand.New(rand.NewSource(time.Now().UnixNano()))

	length := uint64(10000)
	maxRange := uint64(3 * 24 * 60 * 60)
	maxUpperBound := uint64(100 * 365 * 24 * 60 * 60)
	lowerBound, sequence := generateFixedRangeSequence(rand, length, maxRange, maxUpperBound)

	t.Logf("Number of integers to compress: (%v). The lower bound is (%v). The upper bound is (%v)",
		length, lowerBound, lowerBound+maxRange)
	encoding := EncodeUint64Array(sequence)

	// Flate
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, 9)
	require.NoError(err)
	_, err = w.Write(encoding)
	require.NoError(err)
	require.NoError(w.Close())

	// Gzip
	buf2 := new(bytes.Buffer)
	w2, err := gzip.NewWriterLevel(buf2, flate.BestCompression)
	require.NoError(err)

	_, err = w2.Write(encoding)
	require.NoError(err)
	require.NoError(w2.Close())

	// lzw
	var buf3 bytes.Buffer
	w3 := lzw.NewWriter(&buf3, lzw.MSB, 8)
	_, err = w3.Write(encoding)
	require.NoError(err)
	require.NoError(w3.Close())

	// zlib
	var buf4 bytes.Buffer
	w4, err := zlib.NewWriterLevel(&buf4, flate.BestCompression)
	require.NoError(err)
	_, err = w4.Write(encoding)
	require.NoError(err)
	require.NoError(w4.Close())

	// snappy
	buf5 := snappy.Encode(nil, encoding)

	// s2
	var buf6 bytes.Buffer
	enc := s2.NewWriter(&buf6, s2.WriterBestCompression())
	err = enc.EncodeBuffer(encoding)
	require.NoError(err)
	_, err = enc.CloseIndex()
	require.NoError(err)

	t.Log("# of bits : data set")
	t.Log(8*len(encoding), "Uvarint encoding")
	t.Log(8*len(buf.Bytes()), "Flate compression")
	t.Log(8*len(buf2.Bytes()), "Gzip compression")
	t.Log(8*len(buf3.Bytes()), "Lzw compression")
	t.Log(8*len(buf4.Bytes()), "zlib compression")
	t.Log(8*len(buf5), "snappy compression")
	t.Log(8*len(buf6.Bytes()), "s2 compression")

	ef := NewEFEncoder(sequence)
	t.Log(8*len(ef.ToBytes()), "EFEncoding compression")
	testSequenceEncoding(t, rand, sequence, 0)
}

func testSequenceEncoding(t *testing.T, rand *rand.Rand, sequence []uint64, jumpNumber int) {
	require := require.New(t)

	// Create new encoding of the sequence.
	ef := NewEFEncoder(sequence)
	testSequenceEncodingWithEFEncoder(t, rand, sequence, jumpNumber, ef)

	// Get the encoding bytes and create a new EFEncoder using FromBytes.
	efBytes := bytes.NewReader(ef.ToBytes())
	ef2 := &EFEncoder{}
	require.NoError(ef2.FromBytes(efBytes))
	testSequenceEncodingWithEFEncoder(t, rand, sequence, jumpNumber, ef2)
}

func testSequenceEncodingWithEFEncoder(t *testing.T, rand *rand.Rand, sequence []uint64, jumpNumber int, ef *EFEncoder) {
	require := require.New(t)

	// Check that basic iteration works.
	it, err := ef.GetIterator()
	require.NoError(err)

	var testSeq1 []uint64
	for ; it.Valid(); _, err = it.Next() {
		testSeq1 = append(testSeq1, it.GetValue())
	}
	require.Equal(true, compareSequences(sequence, testSeq1))

	// Check that GetSequence works.
	testSeq2, err := ef.GetSequence()
	require.NoError(err)
	require.Equal(true, compareSequences(sequence, testSeq2))

	// Jump to random positions.
	for ii := 0; ii < jumpNumber; ii++ {
		jumpPosition := rand.Uint64() % uint64(len(sequence))
		require.NoError(it.JumpTo(jumpPosition))
		require.Equal(it.GetValue(), sequence[jumpPosition])
	}

	// Jump to random position then iterate to end.
	for ii := 0; ii < jumpNumber; ii++ {
		jumpPosition := rand.Uint64() % uint64(len(sequence))
		require.NoError(it.JumpTo(jumpPosition))

		for jj := jumpPosition; jj < uint64(len(sequence)); jj++ {
			require.Equal(it.GetValue(), sequence[jj])
			_, err := it.Next()
			require.NoError(err)
		}
	}
}

func TestConsecutiveNumbers(t *testing.T) {
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))
	maxSize := uint64(63)
	for length := uint64(1); length <= maxSize; length++ {
		// generate sequence [0, ..., length-1]
		numbers := make([]uint64, length)
		for ii := uint64(0); ii < length; ii++ {
			numbers = append(numbers, ii)
		}

		testSequenceEncoding(t, rand, numbers, int(length))
	}
}

func testSetRangeVariableLength(t *testing.T, rand *rand.Rand, experiments uint64, numberRange uint64,
	minLength uint64, maxLength uint64, jumpNumber int) {

	for ; experiments > 0; experiments-- {
		length := rand.Uint64()%(maxLength-minLength) + minLength
		_, sequence := generateFixedRangeSequence(rand, length, numberRange, numberRange)
		testSequenceEncoding(t, rand, sequence, jumpNumber)
	}
}

func TestManySequences(t *testing.T) {
	rand := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Test small range
	experiments := uint64(100)
	numberRange := uint64(40)
	minLength := uint64(200)
	maxLength := uint64(400)
	testSetRangeVariableLength(t, rand, experiments, numberRange, minLength, maxLength, 0)

	// Test large length, large range
	experiments = uint64(25)
	numberRange = uint64(10000)
	minLength = uint64(15000)
	maxLength = uint64(16000)
	testSetRangeVariableLength(t, rand, experiments, numberRange, minLength, maxLength, 0)
}
