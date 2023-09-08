package consensus

import (
	"sync"
	"time"
)

// ScheduledTask is a wrapper around time.Timer that allows for scheduling tasks to be executed
// at a later time, with params specified at the time the task is scheduled. This pattern is useful
// for scheduling tasks and capturing all of the params and context needed for them to execute them
// all in one place.
//
// If a task is already scheduled, the previous task is cancelled and the new task is scheduled.
type ScheduledTask[TaskParam any] struct {
	lock  sync.Mutex
	timer *time.Timer
}

func NewScheduledTask[TaskParam any]() *ScheduledTask[TaskParam] {
	return &ScheduledTask[TaskParam]{
		lock:  sync.Mutex{},
		timer: nil,
	}
}

// Cancel the currently scheduled task, if any, and schedule a new task to be executed after the countdown.
func (t *ScheduledTask[TaskParam]) Schedule(countdown time.Duration, param TaskParam, task func(TaskParam)) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}

	// Replacing the timer results in it being garbage collected, so this is entirely safe.
	t.timer = time.AfterFunc(countdown, func() {
		task(param)
	})
}

func (t *ScheduledTask[TaskParam]) Cancel() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}
}
