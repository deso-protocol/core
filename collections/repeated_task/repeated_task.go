package repeated_task

import (
	"sync"
	"time"
)

type state int

const (
	stopped state = iota
	running
)

type RepeatedTask struct {
	state
	mtx        sync.Mutex
	startGroup sync.WaitGroup
	stopGroup  sync.WaitGroup

	exitChan     chan struct{}
	taskExitChan chan struct{}
	task         func(exitChan *chan struct{}) bool
	stopTimeout  time.Duration
}

func NewRepeatedTask(task func(exitChan *chan struct{}) (_success bool), stopTimeout time.Duration) *RepeatedTask {
	return &RepeatedTask{
		task:        task,
		stopTimeout: stopTimeout,
	}
}

func (rt *RepeatedTask) Start() {
	rt.mtx.Lock()
	defer rt.mtx.Unlock()

	if rt.state == running {
		return
	}
	rt.exitChan = make(chan struct{})
	rt.taskExitChan = make(chan struct{})

	rt.startGroup.Add(1)
	rt.stopGroup.Add(1)
	go func() {
		rt.startGroup.Done()
		defer rt.stopGroup.Done()
		for {
			select {
			case <-rt.exitChan:
				return
			default:
				if rt.task(&rt.taskExitChan) {
					return
				}
			}
		}
	}()
	rt.startGroup.Wait()
	rt.state = running
}

func (rt *RepeatedTask) Stop() (_killed bool) {
	rt.mtx.Lock()
	defer rt.mtx.Unlock()

	if rt.state == stopped {
		return
	}
	close(rt.taskExitChan)
	rt.taskExitChan = nil
	close(rt.exitChan)

	stopChan := make(chan struct{})
	go func() {
		rt.stopGroup.Wait()
		close(stopChan)
	}()

	killed := false
	select {
	case <-stopChan:
	case <-time.After(rt.stopTimeout):
		killed = true
	}
	rt.state = stopped
	return killed
}
