package consensus

import (
	"sync"
	"time"
)

// ScheduledTask is a thread-safe wrapper around time.Timer that allows for creating tasks that
// can be scheduled to execute at a later time with pre-specified params. Both the params and the
// task are fully defined at the time of scheduling. Once a task has been scheduled, it cannot
// be modified. However, tasks can be cancelled and rescheduled.
//
// This pattern is useful for spawning off tasks that we want to run after some specified amount
// of time, but still want to have the ability to cancel.
type ScheduledTask[TaskParam any] struct {
	lock     sync.RWMutex
	timer    *time.Timer
	duration time.Duration
}

func NewScheduledTask[TaskParam any]() *ScheduledTask[TaskParam] {
	return &ScheduledTask[TaskParam]{
		lock:  sync.RWMutex{},
		timer: nil,
	}
}

// Schedule a new task to be executed after the countdown duration. If there is an existing scheduled
// task, it will be cancelled and replaced with the new task.
func (t *ScheduledTask[TaskParam]) Schedule(duration time.Duration, param TaskParam, task func(TaskParam)) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}

	// Update the duration struct field so it's available to external callers. This struct
	// field has no other purpose.
	t.duration = duration

	// Replacing the timer results in it being garbage collected, so this is entirely safe.
	t.timer = time.AfterFunc(duration, func() {
		task(param)
	})
}

func (t *ScheduledTask[TaskParam]) Cancel() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}

	t.timer = nil
}

func (t *ScheduledTask[TaskParam]) GetDuration() time.Duration {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.duration
}

func (t *ScheduledTask[TaskParam]) IsScheduled() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()

	return t.timer != nil
}
