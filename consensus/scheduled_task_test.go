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
		time.Sleep(time.Second / 2)

		// The task should have executed so this value will now be 100.
		require.Equal(t, uint64(100), executedTaskParam)

		// Confirm the last duration of the task was 1 microsecond.
		require.Equal(t, time.Microsecond, task.GetDuration())
	}

	// Test long scheduled task that's not expected to execute
	{
		task := NewScheduledTask[uint64]()

		executedTaskParam := uint64(0)
		task.Schedule(time.Hour, 100, func(param uint64) {
			executedTaskParam = param
		})

		// The task should not have executed so this value will remain 0.
		require.Equal(t, uint64(0), executedTaskParam)

		// Confirm the last duration of the task was 1 hour.
		require.Equal(t, time.Hour, task.GetDuration())

		// Cancel the task.
		task.Cancel()
	}
}

func TestConcurrentScheduledTask(t *testing.T) {
	type questionableStruct struct {
		questionableField int
	}

	qvar := &questionableStruct{
		questionableField: 0,
	}
	task := NewScheduledTask[int]()
	task.Schedule(time.Millisecond, 5, func(param int) {
		time.Sleep(15 * time.Millisecond)
		qvar.questionableField = param
	})

	time.Sleep(10 * time.Millisecond)
	_taskWithoutSleep := func() {
		task.Schedule(time.Millisecond, 10, func(param int) {
			qvar.questionableField = param
		})
	}
	_taskWithoutSleep()
	time.Sleep(10 * time.Millisecond)
	_taskWithoutSleep()

	time.Sleep(10 * time.Millisecond)
	// The value will be 10 because the second task will not execute until the first task has finished or never started.
	require.Equal(t, 10, qvar.questionableField)
}
