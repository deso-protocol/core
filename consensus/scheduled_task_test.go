package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScheduledTask(t *testing.T) {

	// Test short scheduled task
	{
		task := NewScheduledTask[uint64]()

		executedTaskParam := uint64(0)
		task.Schedule(time.Microsecond, 100, func(param uint64) {
			executedTaskParam = param
		})
		time.Sleep(time.Second)

		// The task should not have executed so this value will now be 100.
		require.Equal(t, uint64(100), executedTaskParam)
	}

	// Test long scheduled task that's not expected to execute
	{
		task := NewScheduledTask[uint64]()

		executedTaskParam := uint64(0)
		task.Schedule(time.Hour, 100, func(param uint64) {
			executedTaskParam = param
		})
		time.Sleep(time.Second)

		// The task should not have executed so this value will remain 0.
		require.Equal(t, uint64(0), executedTaskParam)
	}
}
