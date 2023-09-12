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

type QuestionableStruct struct {
	questionableField int
}

func (q *QuestionableStruct) ToString() string {
	return fmt.Sprintf("Value: %d", q.questionableField)
}

func TestConcurrentScheduledTask(t *testing.T) {

	qvar := &QuestionableStruct{
		questionableField: 0,
	}
	task := NewScheduledTask[int]()
	task.Schedule(100*time.Millisecond, 5, func(param int) {
		fmt.Println("Task with sleep: Started")
		time.Sleep(250 * time.Millisecond)
		fmt.Println("Task with sleep: After sleep")
		qvar.questionableField = param
		fmt.Println("Task with sleep: Finished")
	})

	time.Sleep(150 * time.Millisecond)
	task.Schedule(time.Millisecond, 10, func(param int) {
		fmt.Println("Task without sleep: Started")
		qvar.questionableField = param
		fmt.Println("Task without sleep: Finished")
	})

	time.Sleep(500 * time.Millisecond)
	// Notice that the value will be 5, even though 10 was scheduled after 5.
	fmt.Println(qvar.ToString())
}
