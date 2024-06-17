package bitset

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitsetStorage(t *testing.T) {
	b := NewBitset()

	// Set every 3rd bit to true for indices 0 through 999.
	// This sets indices 0, 3, 5, 9,... 996, 999 to true.
	for ii := 0; ii < 1000; ii++ {
		if ii%3 == 0 {
			b.Set(ii, true)
		}
	}

	// Set all bits from 1000 through 1009 to false.
	for ii := 1000; ii < 1010; ii++ {
		require.False(t, b.Get(ii))
	}

	// Verify that only every 3rd bit is set to true from indices
	// 0 through 999.
	for ii := 0; ii < 1000; ii++ {
		if ii%3 == 0 {
			require.True(t, b.Get(ii))
		} else {
			require.False(t, b.Get(ii))
		}
	}

	// Verify that no additional bits are set beyond index 999.
	for ii := 1000; ii < 1010; ii++ {
		require.False(t, b.Get(ii))
	}

	// Verify that the size of the bitset is 1000, which means that
	// 1000 bits are used, and the highest index set to true is index 999.
	// All indices beyond are implicitly false.
	require.Equal(t, 1000, b.Size())
}

func TestBitsetByteEncodeDecode(t *testing.T) {
	b := NewBitset()

	// Sets indices 0, 3, 6, 9 to true.
	for ii := 0; ii < 10; ii++ {
		if ii%3 == 0 {
			b.Set(ii, true)
		}
	}

	// Set indices 10 through 19 to false.
	for ii := 10; ii < 20; ii++ {
		require.False(t, b.Get(ii))
	}

	// When byte-encoded in big endian format, the bitset
	// has a value of 10 01001001. The highest index set to
	// true is at index 9.
	byteEncoding := b.ToBytes()

	// When byte encoded, the bitset has size of 2 bytes.
	require.Equal(t, 2, len(byteEncoding))
	require.True(t, byteEncoding[0] == 0b00000010) // index 9 is true
	require.True(t, byteEncoding[1] == 0b01001001) // indices 0, 3, 6 are true

	decodedBitset := NewBitset()
	decodedBitset.FromBytes(byteEncoding)

	// Verify that the decoded bitset has the same size as the original.
	require.Equal(t, b.Size(), decodedBitset.Size())

	// Verify that the decoded bitset has the same values as the original.
	for ii := 0; ii < 10; ii++ {
		require.Equal(t, b.Get(ii), decodedBitset.Get(ii))
	}
}

func TestEmptyBitsetByteEncodeDecode(t *testing.T) {
	b := NewBitset()

	require.Zero(t, b.Size())

	byteEncoding := b.ToBytes()

	require.Zero(t, len(byteEncoding))

	decodedBitset := NewBitset()
	decodedBitset.FromBytes(byteEncoding)

	require.Zero(t, decodedBitset.Size())
}

func TestEquality(t *testing.T) {
	// Test nil bitsets
	{
		var bitset1 *Bitset
		var bitset2 *Bitset

		require.False(t, bitset1.Eq(bitset2))

		require.True(t, bytes.Equal(bitset1.ToBytes(), []byte{}))
		require.Zero(t, (&Bitset{}).FromBytes(nil).Size())
	}

	// Test one nil and one non-nil bitset
	{
		var bitset1 *Bitset
		bitset2 := NewBitset().Set(0, true)

		require.False(t, bitset1.Eq(bitset2))
		require.False(t, bitset2.Eq(bitset1))
	}

	// Test two non-equal non-nil bitsets
	{
		bitset1 := NewBitset().Set(0, true)
		bitset2 := NewBitset().Set(1, true)

		require.False(t, bitset1.Eq(bitset2))
		require.False(t, bitset2.Eq(bitset1))
	}

	// Test two equal non-nil bitsets
	{
		bitset1 := NewBitset().Set(0, true)
		bitset2 := NewBitset().Set(0, true).Set(1, false)

		require.True(t, bitset1.Eq(bitset2))
		require.True(t, bitset2.Eq(bitset1))
	}
}
