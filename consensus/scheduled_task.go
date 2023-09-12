package consensus

import (
	"sync"
	"time"
)

const taskListCapacity = 10

// ScheduledTask is a thread-safe wrapper around time.Timer that allows for creating tasks that
// can be scheduled to execute at a later time with pre-specified params. Both the params and the
// task are fully defined at the time of scheduling. Once a task has been scheduled, it cannot
// be modified. However, tasks can be cancelled and rescheduled. If a task is scheduled while
// an existing task is mid-flight, the new task is ensured to execute after the existing task
// has finished.
//
// This pattern is useful for spawning off tasks that we want to run after some specified amount
// of time, but still want to have the ability to cancel.
type ScheduledTask[TaskParam any] struct {
	lock     sync.RWMutex
	taskLock sync.Mutex
	timer    *time.Timer
	duration time.Duration
	seq      uint64
	taskList chan wrappedTask[TaskParam]
}

func NewScheduledTask[TaskParam any]() *ScheduledTask[TaskParam] {
	return &ScheduledTask[TaskParam]{
		taskList: make(chan wrappedTask[TaskParam], taskListCapacity),
	}
}

// Schedule a new task to be executed after the countdown duration. If there is an existing scheduled
// task, it will be cancelled and replaced with the new task.
func (t *ScheduledTask[TaskParam]) Schedule(duration time.Duration, param TaskParam, task func(TaskParam)) {
	t.lock.Lock()
	defer t.lock.Unlock()
	// The sequence number ensures that stale tasks are terminated.
	t.seq++

	if t.timer != nil {
		t.timer.Stop()
	}

	// Update the duration struct field so it's available to external callers. This struct
	// field has no other purpose.
	t.duration = duration

	// taskInit checks that the task isn't stale.
	taskInit := func(seq uint64) bool {
		t.lock.Lock()
		defer t.lock.Unlock()

		if t.seq != seq {
			return false
		}
		// task isn't stale so we schedule it for execution.
		t.taskList <- wrappedTask[TaskParam]{task, param}
		return true
	}
	// Replacing the timer results in it being garbage collected, so this is entirely safe.
	t.timer = time.AfterFunc(duration, func() {
		if !taskInit(t.seq) {
			return
		}
		t.taskLock.Lock()
		defer t.taskLock.Unlock()
		taskItem := <-t.taskList
		taskItem.task(taskItem.param)
	})
}

func (t *ScheduledTask[TaskParam]) Cancel() {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.seq++

	if t.timer != nil {
		t.timer.Stop()
	}
}

func (t *ScheduledTask[TaskParam]) GetDuration() time.Duration {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.duration
}

type wrappedTask[TaskParam any] struct {
	task  func(TaskParam)
	param TaskParam
}
