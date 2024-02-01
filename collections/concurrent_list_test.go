package collections

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConcurrentList(t *testing.T) {
	cl := NewConcurrentList[int]()
	cl.Add(1)
	cl.Add(2)
	cl.Add(3)

	listSnapshot := cl.GetAll()
	require.Equal(t, []int{1, 2, 3}, listSnapshot)

	cl.Add(4)

	listSnapshot2 := cl.GetAll()
	require.Equal(t, []int{1, 2, 3}, listSnapshot)
	require.Equal(t, []int{1, 2, 3, 4}, listSnapshot2)
}
