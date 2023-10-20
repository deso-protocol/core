package repeated_task

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestRepeatedTask(t *testing.T) {
	require := require.New(t)

	// Test that the task is run repeatedly
	repeatCounter := 0

	task := func(exitChan *chan struct{}) bool {
		// Do nothing
		repeatCounter++
		time.Sleep(2 * time.Millisecond)
		return false
	}

	repeatedTask := NewRepeatedTask(task, 10*time.Millisecond)
	repeatedTask.Start()
	totalWait := 0
	for {
		if totalWait > 1000 {
			t.Fatalf("Task is stuck")
		}
		if repeatCounter > 5 {
			break
		}
		time.Sleep(1 * time.Millisecond)
		totalWait++
	}
	repeatedTask.Stop()

	repeatCounter = 0
	task = func(exitChan *chan struct{}) bool {
		// Do nothing
		repeatCounter++
		time.Sleep(1 * time.Millisecond)
		return repeatCounter > 5
	}
	repeatedTask = NewRepeatedTask(task, 10*time.Millisecond)
	repeatedTask.Start()
	time.Sleep(20 * time.Millisecond)
	require.Equal(6, repeatCounter)
	repeatedTask.Stop()

	// Test that the task is exited when Stop() is called
	callbackChan := make(chan struct{}, 10)
	task2 := func(exitChan *chan struct{}) bool {
		<-*exitChan
		require.Nil(*exitChan)
		callbackChan <- struct{}{}
		return true
	}

	repeatedTask2 := NewRepeatedTask(task2, 10*time.Millisecond)
	repeatedTask2.Start()
	repeatedTask2.Stop()

	select {
	case <-callbackChan:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Task did not exit after Stop() was called")
	}

	// Test that the task is killed if it fails to stop within the stop timeout.
	task3 := func(exitChan *chan struct{}) bool {
		// Do nothing
		time.Sleep(100 * time.Millisecond)
		return true
	}
	repeatedTask3 := NewRepeatedTask(task3, 10*time.Millisecond)
	repeatedTask3.Start()
	killed := repeatedTask3.Stop()
	require.True(killed)
}
