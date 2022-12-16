package lib

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSet(t *testing.T) {
	// Set of strings
	set := NewSet[string]([]string{"a", "b", "c"})
	require.Equal(t, set.Size(), 3)
	require.True(t, set.Includes("c"))
	set.Add("d")
	require.Equal(t, set.Size(), 4)
	set.Remove("c")
	require.Equal(t, set.Size(), 3)
	require.False(t, set.Includes("c"))
	require.Equal(t, set.ToOrderedSlice(), []string{"a", "b", "d"})
	set.Add("e")
	require.Equal(t, set.Size(), 4)
	require.Equal(t, set.ToOrderedSlice(), []string{"a", "b", "d", "e"})
}
