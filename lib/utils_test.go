package lib

import (
	"github.com/stretchr/testify/require"
	"math"
	"testing"
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
