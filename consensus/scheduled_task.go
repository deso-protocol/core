package consensus

import (
	"github.com/pkg/errors"
	"sync"
	"time"
)

type scheduledTaskStatus int

const (
	scheduledTaskStatusNotStarted scheduledTaskStatus = iota
	scheduledTaskStatusStarted
	scheduledTaskStatusFinished
)

const errorScheduledTaskNotFinished = "ScheduledTask has started and must finish before a new task can be scheduled."

// ScheduledTask is a thread-safe wrapper around time.Timer that allows for creating tasks that
// can be scheduled to execute at a later time with pre-specified params. Both the params and the
// task are fully defined at the time of scheduling. Once a task has been scheduled, it cannot
// be modified. However, tasks can be cancelled and rescheduled.
//
// This pattern is useful for spawning off tasks that we want to run after some specified amount
// of time, but still want to have the ability to cancel.
type ScheduledTask[TaskParam any] struct {
	status   scheduledTaskStatus
	seq      uint64
	lock     sync.RWMutex
	timer    *time.Timer
	duration time.Duration
}

func NewScheduledTask[TaskParam any]() *ScheduledTask[TaskParam] {
	return &ScheduledTask[TaskParam]{
		status: scheduledTaskStatusNotStarted,
		seq:    0,
		lock:   sync.RWMutex{},
		timer:  nil,
	}
}

// Schedule a new task to be executed after the countdown duration. If there is an existing scheduled
// task, it will be cancelled and replaced with the new task.
func (t *ScheduledTask[TaskParam]) Schedule(duration time.Duration, param TaskParam, task func(TaskParam)) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status == scheduledTaskStatusStarted {
		return errors.New(errorScheduledTaskNotFinished)
	}
	t.status = scheduledTaskStatusNotStarted
	t.seq++

	if t.timer != nil {
		t.timer.Stop()
	}

	// Update the duration struct field so it's available to external callers. This struct
	// field has no other purpose.
	t.duration = duration

	// Replacing the timer results in it being garbage collected, so this is entirely safe.
	taskFunc := func(seq uint64) {
		t.lock.Lock()
		defer t.lock.Unlock()

		if t.seq != seq {
			return
		}
		t.status = scheduledTaskStatusStarted
	}
	t.timer = time.AfterFunc(duration, func() {
		taskFunc(t.seq)
		task(param)

		t.lock.Lock()
		defer t.lock.Unlock()
		t.status = scheduledTaskStatusFinished
	})

	return nil
}

func (t *ScheduledTask[TaskParam]) Cancel() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.status == scheduledTaskStatusStarted {
		return
	}
	t.status = scheduledTaskStatusNotStarted
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
