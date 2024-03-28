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
//
// Note: There is a race condition in which a scheduled task is rescheduled at the same moment the
// previously scheduled task begins to execute. This gives the appearance from the caller's POV that
// the previous task executed, despite being replaced. There is no simple internal-only solution to
// prevent, in a way that guarantees no risk of deadlock with outside code's mutexes. If such race
// conditions are a concern, the caller must internally validate the provided param to ensure its
// attached task is no longer stale. See FastHotStuffEventLoop.onTimeoutScheduledTaskExecuted(view uint64)
// for a simple example that exits task execution early when the view param is stale.
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

// Note: The same race condition as above exists, in which a scheduled task is cancelled at the same moment
// it is begins to execute. If such race conditions are a concern, the caller must internally validate the
// provided param to ensure its attached task is no longer stale, similar to the above.
func (t *ScheduledTask[TaskParam]) Cancel() {
	t.lock.Lock()
	defer t.lock.Unlock()

	if t.timer != nil {
		t.timer.Stop()
	}

	t.timer = nil
	t.duration = 0
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
