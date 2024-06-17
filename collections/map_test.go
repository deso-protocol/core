package collections

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMap(t *testing.T) {
	control := make(map[string]int)

	for ii := 0; ii < 100; ii++ {
		key := fmt.Sprintf("%v", ii)
		control[key] = ii
	}

	// Test Contains
	for ii := 0; ii < 100; ii++ {
		require.True(t, MapContains(control, fmt.Sprintf("%v", ii)))
	}

	// Make sure Contains doesn't return true for a key that doesn't exist
	require.False(t, MapContains(control, "not exists"))

	// Test MapValues
	values := MapValues(control)
	for ii := 0; ii < 100; ii++ {
		require.Contains(t, values, ii)
	}
}
