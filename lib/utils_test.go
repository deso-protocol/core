package lib

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeMakeSliceWithLength(t *testing.T) {
	badSlice, err := SafeMakeSliceWithLength[byte](math.MaxUint64)
	require.NotNil(t, err)
	require.Nil(t, badSlice)

	goodSlice, err := SafeMakeSliceWithLength[byte](10)
	require.Nil(t, err)
	require.Len(t, goodSlice, 10)
}

func TestSafeMakeSliceWithLengthAndCapacity(t *testing.T) {
	badSliceLength, err := SafeMakeSliceWithLengthAndCapacity[byte](math.MaxUint64-10, 0)
	require.NotNil(t, err)
	require.Nil(t, badSliceLength)

	badSliceCapacity, err := SafeMakeSliceWithLengthAndCapacity[byte](10, math.MaxUint64)
	require.NotNil(t, err)
	require.Nil(t, badSliceCapacity)

	goodSlice, err := SafeMakeSliceWithLength[byte](10)
	require.Nil(t, err)
	require.Len(t, goodSlice, 10)
}

// Note: I can't find a capacity that breaks the make map function
func TestSafeMakeMapWithCapacity(t *testing.T) {
	goodMap, err := SafeMakeMapWithCapacity[string, []byte](1000)
	require.Nil(t, err)
	require.NotNil(t, goodMap)
}

func TestHashUint64ToUint64(t *testing.T) {
	require.Equal(t, uint64(0x48dda5bbe9171a66), hashUint64ToUint64(0))
	require.Equal(t, uint64(0x6c70d57af53dbf4d), hashUint64ToUint64(1))
	require.Equal(t, uint64(0xf90387edb7755d08), hashUint64ToUint64(2))
	require.Equal(t, uint64(0x6168e462f883acea), hashUint64ToUint64(3))
	require.Equal(t, uint64(0xeb667cfa9fe822a), hashUint64ToUint64(4))
	require.Equal(t, uint64(0x14534c98fc4f74a5), hashUint64ToUint64(5))
	require.Equal(t, uint64(0x821888e817f3332d), hashUint64ToUint64(6))
	require.Equal(t, uint64(0x660352baa787b9a3), hashUint64ToUint64(7))
	require.Equal(t, uint64(0xe16e2c6a637a34d7), hashUint64ToUint64(8))
	require.Equal(t, uint64(0x883c56385fb82c1d), hashUint64ToUint64(9))
	require.Equal(t, uint64(0xdb0c9e58da328e78), hashUint64ToUint64(10))
}
