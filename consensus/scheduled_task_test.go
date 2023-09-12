package consensus

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScheduledTask(t *testing.T) {

	// Test short scheduled task
	{
		task := NewScheduledTask[uint64]()

		executedTaskParam := uint64(0)
		err := task.Schedule(time.Microsecond, 100, func(param uint64) {
			executedTaskParam = param
		})
		require.NoError(t, err)
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
		err := task.Schedule(time.Hour, 100, func(param uint64) {
			executedTaskParam = param
		})
		require.NoError(t, err)

		// The task should not have executed so this value will remain 0.
		require.Equal(t, uint64(0), executedTaskParam)

		// Confirm the last duration of the task was 1 hour.
		require.Equal(t, time.Hour, task.GetDuration())

		// Cancel the task.
		task.Cancel()
	}
}

type questionableStruct struct {
	questionableField int
}

func (q *questionableStruct) ToString() string {
	return fmt.Sprintf("Value: %d", q.questionableField)
}

func TestConcurrentScheduledTask(t *testing.T) {

	qvar := &questionableStruct{
		questionableField: 0,
	}
	task := NewScheduledTask[int]()
	err := task.Schedule(time.Millisecond, 5, func(param int) {
		fmt.Println("Task with sleep: Started")
		time.Sleep(15 * time.Millisecond)
		fmt.Println("Task with sleep: After sleep")
		qvar.questionableField = param
		fmt.Println("Task with sleep: Finished")
	})
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	_taskWithoutSleep := func() {
		err = task.Schedule(time.Millisecond, 10, func(param int) {
			fmt.Println("Task without sleep: Started")
			qvar.questionableField = param
			fmt.Println("Task without sleep: Finished")
		})
	}
	_taskWithoutSleep()
	if err != nil {
		fmt.Println("Task without sleep: Cant start, error:", err)
	}
	time.Sleep(10 * time.Millisecond)
	fmt.Println("Task without sleep: Waited, retrying")
	_taskWithoutSleep()
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	// The value will be 10 because the second task will not execute until the first task has finished or never started.
	fmt.Println(qvar.ToString())
}
