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
