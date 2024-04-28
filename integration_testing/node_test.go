package integration_testing

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/deso-protocol/core/cmd"

	"github.com/stretchr/testify/require"
)

func TestNodeIsRunning(t *testing.T) {
	testDir := getDirectory(t)
	defer os.RemoveAll(testDir)

	testConfig := generateConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := cmd.NewNode(testConfig)

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

func TestNodeStatusRunningWithoutLock(t *testing.T) {
	testDir := getDirectory(t)
	defer os.RemoveAll(testDir)

	testConfig := generateConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := cmd.NewNode(testConfig)

	// Can change the status to RUNNING from the state NEVERSTARTED
	actualErr := testNode.SetStatusRunningWithoutLock()
	require.NoError(t, actualErr)

	// Change status from RUNNING to STOPPED
	actualErr = testNode.SetStatusStoppedWithoutLock()
	require.NoError(t, actualErr)

	// start the server
	// Cannot change status to RUNNING while the node is already RUNNING!
	testNode.Start()
	expErr := cmd.ErrAlreadyStarted
	actualErr = testNode.SetStatusRunningWithoutLock()
	require.ErrorIs(t, actualErr, expErr)

	// Stop the node
	testNode.Stop()
	// Should be able to change status to RUNNING from STOP.
	actualErr = testNode.SetStatusRunningWithoutLock()
	require.NoError(t, actualErr)
	// Once the running flag is changed, the isRunning function should return true
	require.True(t, testNode.IsRunning())

}

func TestNodeSetStatusStoppedWithoutLock(t *testing.T) {
	testDir := getDirectory(t)
	defer os.RemoveAll(testDir)

	testConfig := generateConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := cmd.NewNode(testConfig)

	// Need to call node.start() to atleast once to be able to change node status
	// Cannot change status of node which never got initialized in the first place
	expErr := cmd.ErrNodeNeverStarted
	actualErr := testNode.SetStatusStoppedWithoutLock()
	require.ErrorIs(t, actualErr, expErr)

	// start the node
	// Should be able to successfully change the status of the node
	// Once the server is started
	testNode.Start()

	actualErr = testNode.SetStatusStoppedWithoutLock()
	require.NoError(t, actualErr)

	// stop the node
	testNode.Stop()

	expErr = cmd.ErrAlreadyStopped
	actualErr = testNode.SetStatusStoppedWithoutLock()
	require.ErrorIs(t, actualErr, expErr)
}

// Node status is change in the following sequence,
// NEVERSTARTED -> RUNNING -> STOP -> RUNNING
// In each state change it's tested for valid change in status.
func TestNodeSetStatus(t *testing.T) {
	testDir := getDirectory(t)
	defer os.RemoveAll(testDir)

	testConfig := generateConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := cmd.NewNode(testConfig)

	// Node is in NEVERSTARTED STATE

	// Changing status from NEVERSTARTED to STOPPED
	// This is an invalid status transition.
	// Node status cannot needs to transitioned to RUNNING before changing to STOPPED
	expError := cmd.ErrNodeNeverStarted
	actualError := testNode.SetStatus(cmd.STOPPED)
	require.ErrorIs(t, actualError, expError)

	// Cannot set the status to NEVERSTARTED,
	// It's the default value before the Node is initialized.
	expError = cmd.ErrCannotSetToNeverStarted
	actualError = testNode.SetStatus(cmd.NEVERSTARTED)
	require.ErrorIs(t, actualError, expError)
	// Starting the node.
	// The current status of the node is RUNNING.
	testNode.Start()
	// The status should be changed to RUNNING.
	// This successfully tests the transition of status from NEVERSTARTED to RUNNING
	expectedStatus := cmd.RUNNING
	actualStatus, err := testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Cannot set the status to NEVERSTARTED,
	// It's the default value before the Node is initialized.
	expError = cmd.ErrCannotSetToNeverStarted
	actualError = testNode.SetStatus(cmd.NEVERSTARTED)
	require.ErrorIs(t, actualError, expError)

	// Cannot expect the Node status to changed from STOPPED to RUNNING,
	// while it's current state is RUNNING
	expError = cmd.ErrAlreadyStarted
	actualError = testNode.SetStatus(cmd.RUNNING)
	require.ErrorIs(t, actualError, expError)

	// Stopping the node.
	// This should transition the Node state from RUNNING to STOPPED.
	testNode.Stop()
	expectedStatus = cmd.STOPPED
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Cannot set the status to NEVERSTARTED,
	// It's the default value before the Node is initialized.
	expError = cmd.ErrCannotSetToNeverStarted
	actualError = testNode.SetStatus(cmd.NEVERSTARTED)
	require.ErrorIs(t, actualError, expError)

	// Cannot expect the Node status to changed from NEVERSTARTED to STOPPED,
	// while it's current state is STOPPED
	expError = cmd.ErrAlreadyStopped
	actualError = testNode.SetStatus(cmd.STOPPED)
	require.ErrorIs(t, actualError, expError)

	// Changing status from STOPPED to RUNNING
	testNode.Start()
	// The following tests validates a successful transition of state from STOP to RUNNING
	expectedStatus = cmd.RUNNING
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)
	testNode.Stop()

	// Set the Node status to an invalid status code
	// protects from the ignorance of adding new status codes to the iota sequence!
	expError = cmd.ErrInvalidNodeStatus
	actualError = testNode.SetStatus(cmd.NodeStatus(3))
	require.ErrorIs(t, actualError, expError)

	expError = cmd.ErrInvalidNodeStatus
	actualError = testNode.SetStatus(cmd.NodeStatus(4))
	require.ErrorIs(t, actualError, expError)

	expError = cmd.ErrInvalidNodeStatus
	actualError = testNode.SetStatus(cmd.NodeStatus(5))
	require.ErrorIs(t, actualError, expError)

}

// Tests for *Node.GetStatus()
// Loads the status of node after node operations and tests its correctness.
func TestGetStatus(t *testing.T) {
	testDir := getDirectory(t)
	defer os.RemoveAll(testDir)

	testConfig := generateConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := cmd.NewNode(testConfig)

	// Status is set to NEVERSTARTED before the node is started.
	expectedStatus := cmd.NEVERSTARTED
	actualStatus, err := testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Start the node
	testNode.Start()

	// The status is expected to be RUNNING once the node is started.
	expectedStatus = cmd.RUNNING
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// Stop the node.
	testNode.Stop()

	// The status is expected to be STOPPED once the node is stopped.
	expectedStatus = cmd.STOPPED
	actualStatus, err = testNode.GetStatus()
	require.NoError(t, err)
	require.Equal(t, actualStatus, expectedStatus)

	// set an invalid status
	wrongStatus := cmd.NodeStatus(5)
	err = testNode.SetStatus(wrongStatus)
	require.Error(t, err)
	// Commenting this out as I can't set a wrong status
	// maybe there's a way to do this to get more coverage,
	// but I'd rather have everything in the integration testing file
	//// expect error and invalid status code
	//expectedStatus = cmd.INVALIDNODESTATUS
	//actualStatus, err = testNode.GetStatus()
	//require.ErrorIs(t, err, cmd.ErrInvalidNodeStatus)
	//require.Equal(t, actualStatus, expectedStatus)
}

func TestValidateNodeStatus(t *testing.T) {

	inputs := []cmd.NodeStatus{cmd.NEVERSTARTED, cmd.RUNNING, cmd.STOPPED, cmd.NodeStatus(3), cmd.NodeStatus(4)}
	errors := []error{nil, nil, nil, cmd.ErrInvalidNodeStatus, cmd.ErrInvalidNodeStatus}

	var err error
	for i := 0; i < len(inputs); i++ {
		err = cmd.ValidateNodeStatus(inputs[i])
		require.ErrorIs(t, err, errors[i])
	}
}

// Stop the node and test whether the internalExitChan fires as expected.
func TestNodeStop(t *testing.T) {
	testDir := getDirectory(t)
	defer os.RemoveAll(testDir)

	testConfig := generateConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := cmd.NewNode(testConfig)
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
