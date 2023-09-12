package consensus

import (
	"github.com/pkg/errors"
	"sync"
	"time"
)

// scheduledTaskStatus represents the status of the task that is scheduled.
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

	// If the task has already started, we can't schedule a new one. Instead, we will let the caller know to wait
	// for the task to finish.
	if t.status == scheduledTaskStatusStarted {
		return errors.New(errorScheduledTaskNotFinished)
	}
	// We can now safely assume that the task has not started. We reset the status and increment the sequence number.
	// The sequence number is ensures that stale tasks are terminated.
	t.status = scheduledTaskStatusNotStarted
	t.seq++

	if t.timer != nil {
		t.timer.Stop()
	}

	// Update the duration struct field so it's available to external callers. This struct
	// field has no other purpose.
	t.duration = duration

	// taskInit checks that the task isn't stale and updates the status to started.
	taskInit := func(seq uint64) bool {
		t.lock.Lock()
		defer t.lock.Unlock()

		if t.seq != seq {
			return false
		}
		t.status = scheduledTaskStatusStarted
		return true
	}
	// Replacing the timer results in it being garbage collected, so this is entirely safe.
	t.timer = time.AfterFunc(duration, func() {
		if !taskInit(t.seq) {
			return
		}
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
