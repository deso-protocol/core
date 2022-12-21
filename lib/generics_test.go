package lib

import (
	"github.com/pkg/errors"
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
	mappedSet, err := MapSet(set, func(elem string) (string, error) {
		return elem + "!", nil
	})
	require.NoError(t, err)
	require.Contains(t, mappedSet, "a!")
	require.Contains(t, mappedSet, "b!")
	require.Contains(t, mappedSet, "d!")
	counter := 0
	nilSet, err := MapSet(set, func(elem string) (string, error) {
		if counter == 1 {
			return "", errors.New("TESTERROR")
		}
		counter++
		return elem, nil
	})
	require.Error(t, err)
	require.Equal(t, err.Error(), "TESTERROR")
	require.Nil(t, nilSet)
}
