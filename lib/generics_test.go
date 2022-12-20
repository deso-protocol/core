package lib

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSet(t *testing.T) {
	// Set of strings
	set := NewSet([]string{"a", "b", "c"})
	require.Equal(t, set.Size(), 3)
	require.True(t, set.Includes("c"))
	set.Add("d")
	require.Equal(t, set.Size(), 4)
	set.Remove("c")
	require.Equal(t, set.Size(), 3)
	require.False(t, set.Includes("c"))
	toSlice := set.ToSlice()
	require.Contains(t, toSlice, "a")
	require.Contains(t, toSlice, "b")
	require.Contains(t, toSlice, "d")
	set.Add("e")
	require.Equal(t, set.Size(), 4)
	mappedSet := []string{}
	err := set.ForEach(func(elem string) error {
		mappedSet = append(mappedSet, elem+"!")
		return nil
	})
	require.NoError(t, err)
	require.Contains(t, mappedSet, "a!")
	require.Contains(t, mappedSet, "b!")
	require.Contains(t, mappedSet, "d!")
}
