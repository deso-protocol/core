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
	require.Equal(t, uint64(0xb44fe43833aee9df), hashUint64ToUint64(0))
	require.Equal(t, uint64(0x108b92bbec8ac907), hashUint64ToUint64(1))
	require.Equal(t, uint64(0x5e3069e98b0a92a3), hashUint64ToUint64(2))
	require.Equal(t, uint64(0x8c37fe80be5069da), hashUint64ToUint64(3))
	require.Equal(t, uint64(0xb7193cad15e9dacb), hashUint64ToUint64(4))
	require.Equal(t, uint64(0xee882a10cf97f481), hashUint64ToUint64(5))
	require.Equal(t, uint64(0xc461aeb9e0bc743), hashUint64ToUint64(6))
	require.Equal(t, uint64(0x593213a820d4b0f6), hashUint64ToUint64(7))
	require.Equal(t, uint64(0x2129df009fbe92e2), hashUint64ToUint64(8))
	require.Equal(t, uint64(0xb1f42d10c6eaa340), hashUint64ToUint64(9))
	require.Equal(t, uint64(0x4783353a3997ebd1), hashUint64ToUint64(10))
}
