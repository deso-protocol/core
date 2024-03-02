package collections

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSliceAll(t *testing.T) {
	// Predicate: all values > 0
	predicate := func(val int) bool {
		return val > 0
	}

	// Test sad path where no values are > 0
	{
		slice := []int{-1, -2, -3, -4, -5}
		require.False(t, All(slice, predicate))
	}

	// Test sad path where some values are > 0
	{
		slice := []int{-1, 2, 3, 4, 5}
		require.False(t, All(slice, predicate))
	}

	// Test happy path where all values are > 0
	{
		slice := []int{1, 2, 3, 4, 5}
		require.True(t, All(slice, predicate))
	}
}

func TestSliceAny(t *testing.T) {
	// Predicate: all values > 0
	predicate := func(val int) bool {
		return val > 0
	}

	// Test sad path where no values are > 0
	{
		slice := []int{-1, -2, -3, -4, -5}
		require.False(t, Any(slice, predicate))
	}

	// Test happy path where some values are > 0
	{
		slice := []int{-1, 2, 3, 4, 5}
		require.True(t, Any(slice, predicate))
	}

	// Test happy path where all values are > 0
	{
		slice := []int{1, 2, 3, 4, 5}
		require.True(t, Any(slice, predicate))
	}
}

func TestSliceToMap(t *testing.T) {
	// Create a struct to test the slice -> map transformation
	type keyValueType struct {
		Key   string
		Value string
	}

	// Test empty slice
	{
		// Create a custom function extract the key from the struct
		keyFn := func(val keyValueType) string {
			return val.Key
		}

		slice := []keyValueType{}
		result := ToMap(slice, keyFn)
		require.Equal(t, 0, len(result))
	}

	// Test slice with pointers
	{
		// Create a custom function extract the key from the struct
		keyFn := func(val *keyValueType) string {
			return val.Key
		}

		slice := []*keyValueType{
			{Key: "a", Value: "1"},
			{Key: "b", Value: "2"},
		}
		result := ToMap(slice, keyFn)
		require.Equal(t, 2, len(result))
		require.Equal(t, "1", result["a"].Value)
		require.Equal(t, "2", result["b"].Value)
	}

	// Test slice with raw values
	{
		// Create a custom function extract the key from the struct
		keyFn := func(val keyValueType) string {
			return val.Key
		}

		slice := []keyValueType{
			{Key: "a", Value: "1"},
			{Key: "b", Value: "2"},
		}
		result := ToMap(slice, keyFn)
		require.Equal(t, 2, len(result))
		require.Equal(t, "1", result["a"].Value)
		require.Equal(t, "2", result["b"].Value)
	}
}

func TestRemoveDuplicates(t *testing.T) {
	// Test empty slices
	{
		slices1 := []int{}
		slices2 := []int{}

		slice1Unique, slice2Unique := RemoveDuplicates(slices1, slices2)

		require.Equal(t, 0, len(slice1Unique))
		require.Equal(t, 0, len(slice2Unique))
	}

	// Test slices with no duplicates
	{
		slices1 := []int{1, 2, 3, 4, 5}
		slices2 := []int{6, 7, 8, 9, 10}

		slice1Unique, slice2Unique := RemoveDuplicates(slices1, slices2)

		require.Equal(t, slices1, slice1Unique)
		require.Equal(t, slices2, slice2Unique)
	}

	// Test slices with only duplicates
	{
		slices1 := []int{1, 2, 3, 4, 5}
		slices2 := []int{1, 2, 3, 4, 5}

		slice1Unique, slice2Unique := RemoveDuplicates(slices1, slices2)

		require.Equal(t, 0, len(slice1Unique))
		require.Equal(t, 0, len(slice2Unique))
	}

	// Test slices with both duplicate and unique values
	{
		slices1 := []int{1, 2, 3, 4, 5}
		slices2 := []int{2, 3, 4, 5, 6, 7, 8, 9, 10}

		slice1Unique, slice2Unique := RemoveDuplicates(slices1, slices2)

		require.Equal(t, slice1Unique, []int{1})
		require.Equal(t, slice2Unique, []int{6, 7, 8, 9, 10})
	}
}

func TestFilter(t *testing.T) {
	// Predicate: all values > 0
	predicate := func(val int) bool {
		return val > 0
	}

	// Test example where no values are > 0
	{
		slice := []int{-1, -2, -3, -4, -5}
		result := Filter(slice, predicate)
		require.Equal(t, 0, len(result))
	}

	// Test example where some values are > 0
	{
		slice := []int{-1, 2, 3, 4, 5}
		result := Filter(slice, predicate)
		require.Equal(t, 4, len(result))
		require.Equal(t, []int{2, 3, 4, 5}, result)
	}

	// Test example where all values are > 0
	{
		slice := []int{1, 2, 3, 4, 5}
		result := Filter(slice, predicate)
		require.Equal(t, 5, len(result))
		require.Equal(t, []int{1, 2, 3, 4, 5}, result)
	}
}
