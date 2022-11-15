package cmd

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNodeIsRunning(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_is_running")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// expected running status should be false before the node is started
	require.False(t, testNode.IsRunning())

	// Start the node
	testNode.Start()
	// expected running status should be true after the server is started
	require.True(t, testNode.IsRunning())

	// stop the node
	testNode.Stop()
	require.False(t, testNode.IsRunning())

}

func TestNodeStatusRunning(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_change_running_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Can change the status to RUNNING from the state NEVERSTARTED
	actualErr := testNode.UpdateStatusRunning()
	require.NoError(t, actualErr)

	// Change status from RUNNING to STOPPED
	actualErr = testNode.UpdateStatusStopped()
	require.NoError(t, actualErr)

	// start the server
	// Cannot change status to RUNNING while the node is already RUNNING!
	testNode.Start()
	expErr := ErrAlreadyStarted
	actualErr = testNode.UpdateStatusRunning()
	require.ErrorIs(t, actualErr, expErr)

	// Stop the node
	testNode.Stop()
	// Should be able to change status to RUNNING from STOP.
	actualErr = testNode.UpdateStatusRunning()
	require.NoError(t, actualErr)
	// Once the running flag is changed, the isRunning function should return true
	require.True(t, testNode.IsRunning())

}

func TestNodeUpdateStatusStopped(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_change_running_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Need to call node.start() to atleast once to be able to change node status
	// Cannot change status of node which never got initialized in the first place
	expErr := ErrNodeNeverStarted
	actualErr := testNode.UpdateStatusStopped()
	require.ErrorIs(t, actualErr, expErr)

	// start the node
	// Should be able to successfully change the status of the node
	// Once the server is started
	testNode.Start()

	actualErr = testNode.UpdateStatusStopped()
	require.NoError(t, actualErr)

	// stop the node
	testNode.Stop()

	expErr = ErrAlreadyStopped
	actualErr = testNode.UpdateStatusStopped()
	require.ErrorIs(t, actualErr, expErr)
}

// Node status is change in the following sequence,
// NEVERSTARTED -> RUNNING -> STOP -> RUNNING
// In each state change it's tested for valid change in status.
func TestNodeUpdateStatus(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_change_running_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Node is in NEVERSTARTED STATE

	// Changing status from NEVERSTARTED to STOPPED
	// This is an invalid status transition.
	// Node status cannot needs to transitioned to RUNNING before changing to STOPPED
	expError := ErrNodeNeverStarted
	actualError := testNode.UpdateStatus(STOPPED)
	require.ErrorIs(t, actualError, expError)

	// Cannot set the status to NEVERSTARTED,
	// It's the default value before the Node is initialized.
	expError = ErrCannotSetToNeverStarted
	actualError = testNode.UpdateStatus(NEVERSTARTED)
	require.ErrorIs(t, actualError, expError)
	// Starting the node.
	// The current status of the node is RUNNING.
	testNode.Start()
	// The status should be changed to RUNNING.
	// This successfully tests the transition of status from NEVERSTARTED to RUNNING
	expectedStatus := RUNNING
	actualStatus, err := testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Cannot set the status to NEVERSTARTED,
	// It's the default value before the Node is initialized.
	expError = ErrCannotSetToNeverStarted
	actualError = testNode.UpdateStatus(NEVERSTARTED)
	require.ErrorIs(t, actualError, expError)

	// Cannot expect the Node status to changed from STOPPED to RUNNING,
	// while it's current state is RUNNING
	expError = ErrAlreadyStarted
	actualError = testNode.UpdateStatus(RUNNING)
	require.ErrorIs(t, actualError, expError)

	// Stopping the node.
	// This should transition the Node state from RUNNING to STOPPED.
	testNode.Stop()
	expectedStatus = STOPPED
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Cannot set the status to NEVERSTARTED,
	// It's the default value before the Node is initialized.
	expError = ErrCannotSetToNeverStarted
	actualError = testNode.UpdateStatus(NEVERSTARTED)
	require.ErrorIs(t, actualError, expError)

	// Cannot expect the Node status to changed from NEVERSTARTED to STOPPED,
	// while it's current state is STOPPED
	expError = ErrAlreadyStopped
	actualError = testNode.UpdateStatus(STOPPED)
	require.ErrorIs(t, actualError, expError)

	// Changing status from STOPPED to RUNNING
	testNode.Start()
	// The following tests validates a successful transition of state from STOP to RUNNING
	expectedStatus = RUNNING
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)
	testNode.Stop()

	// Set the Node status to an invalid status code
	// protects from the ignorance of adding new status codes to the iota sequence!
	expError = ErrInvalidNodeStatus
	actualError = testNode.UpdateStatus(NodeStatus(3))
	require.ErrorIs(t, actualError, expError)

	expError = ErrInvalidNodeStatus
	actualError = testNode.UpdateStatus(NodeStatus(4))
	require.ErrorIs(t, actualError, expError)

	expError = ErrInvalidNodeStatus
	actualError = testNode.UpdateStatus(NodeStatus(5))
	require.ErrorIs(t, actualError, expError)

}

// Tests for *Node.GetStatus()
// Loads the status of node after node operations and tests its correctness.
func TestGetStatus(t *testing.T) {
	testDir := getTestDirectory(t, "test_load_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Status is set to NEVERSTARTED before the node is started.
	expectedStatus := NEVERSTARTED
	actualStatus, err := testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Start the node
	testNode.Start()

	// The status is expected to be RUNNING once the node is started.
	expectedStatus = RUNNING
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Stop the node.
	testNode.Stop()

	// The status is expected to be STOPPED once the node is stopped.
	expectedStatus = STOPPED
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// set an invalid status
	wrongStatus := NodeStatus(5)
	testNode.status = &wrongStatus

	// expect error and invalid status code
	expectedStatus = INVALIDNODESTATUS
	actualStatus, err = testNode.GetStatus()
	require.ErrorIs(t, err, ErrInvalidNodeStatus)
	require.Equal(t, actualStatus, expectedStatus)
}

func TestValidateNodeStatus(t *testing.T) {

	inputs := []NodeStatus{NEVERSTARTED, RUNNING, STOPPED, NodeStatus(3), NodeStatus(4)}
	errors := []error{nil, nil, nil, ErrInvalidNodeStatus, ErrInvalidNodeStatus}

	var err error
	for i := 0; i < len(inputs); i++ {
		err = validateNodeStatus(inputs[i])
		require.ErrorIs(t, err, errors[i])
	}
}

// Stop the node and test whether the internalExitChan fires as expected.
func TestNodeStop(t *testing.T) {
	testDir := getTestDirectory(t, "test_load_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)
	testNode.Start()

	// stop the node
	go func() {
		err := testNode.Stop()
		require.NoError(t, err)
	}()

	// Test whether the node stops successfully under three seconds.
	select {
	case <-testNode.Quit():
	case <-time.After(3 * time.Second):
		pid := os.Getpid()
		p, err := os.FindProcess(pid)
		if err != nil {
			panic(err)
		}
		err = p.Signal(syscall.SIGABRT)
		fmt.Println(err)
		t.Fatal("timed out waiting for shutdown")
	}
}
