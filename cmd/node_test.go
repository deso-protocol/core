package cmd

import (
	"os"
	"testing"

	//"github.com/deso-protocol/core/lib"
	//"github.com/deso-protocol/core/lib"
	"github.com/stretchr/testify/require"
)

func TestNodeIsRunning(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_is_running")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// expected running status should be false before the node is started
	expectedRunningStatus := false
	actualRunningstatus := testNode.IsRunning()
	require.Equal(t, expectedRunningStatus, actualRunningstatus)

	// Start the node
	testNode.Start()
	// expected running status should be true after the server is started
	expectedRunningStatus = true
	actualRunningstatus = testNode.IsRunning()
	require.Equal(t, expectedRunningStatus, actualRunningstatus)

	// stop the node
	testNode.Stop()
	expectedRunningStatus = false
	actualRunningstatus = testNode.IsRunning()
	require.Equal(t, expectedRunningStatus, actualRunningstatus)

}

func TestNodeStatusStopToStart(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_change_running_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Need to call node.start() to atleast once to be able to change the running status of a node
	// Cannot change status of node which never got initialized in the first place
	expErr := ErrNodeNeverStarted
	actualErr := testNode.StatusStopToStart()
	require.ErrorIs(t, expErr, actualErr)

	// start the server
	// Cannot change the running status of a node from stop to start while
	// the node is still running
	testNode.Start()
	expErr = ErrAlreadyStarted
	actualErr = testNode.StatusStopToStart()
	require.ErrorIs(t, expErr, actualErr)

	// Stop the node
	// Should successfully change the status from stop to start after the node is stopped
	// expect no error
	testNode.Stop()
	actualErr = testNode.StatusStopToStart()
	require.NoError(t, actualErr)
	// Once the running flag is changed, the isRunning function should return true
	require.Equal(t, true, testNode.IsRunning())

}

func TestNodeStatusStartToStop(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_change_running_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Need to call node.start() to atleast once to be able to change node status
	// Cannot change status of node which never got initialized in the first place
	expErr := ErrNodeNeverStarted
	actualErr := testNode.StatusStartToStop()
	require.ErrorIs(t, expErr, actualErr)

	// start the node
	// Should be able to successfully change the status of the node
	// Once the server is started
	testNode.Start()

	actualErr = testNode.StatusStartToStop()
	require.NoError(t, actualErr)

	// stop the node
	testNode.Stop()

	expErr = ErrAlreadyStopped
	actualErr = testNode.StatusStartToStop()
	require.ErrorIs(t, expErr, actualErr)
}

func TestNodeChangeRunningStatus(t *testing.T) {
	testDir := getTestDirectory(t, "test_node_change_running_status")
	defer os.RemoveAll(testDir)

	testConfig := GenerateTestConfig(t, 18000, testDir, 10)

	testConfig.ConnectIPs = []string{"deso-seed-2.io:17000"}

	testNode := NewNode(&testConfig)

	// Need to call node.start() to atleast once to be able to change the running status of a node
	// Cannot change status of node which never got initialized in the first place
	expError := ErrNodeNeverStarted
	// Changing status from false to true
	actualError := changeRunningStatus(testNode, false, true)
	require.ErrorIs(t, expError, actualError)
	// Changing status from true to false
	actualError = changeRunningStatus(testNode, true, false)
	require.ErrorIs(t, expError, actualError)

	// start the node
	testNode.Start()

	// Cannot change node running status to true while it's running
	// its already set to true
	expError = ErrAlreadyStarted
	actualError = changeRunningStatus(testNode, false, true)
	require.ErrorIs(t, expError, actualError)

	// Should be able to change the node running status to false once started
	actualError = changeRunningStatus(testNode, true, false)
	require.NoError(t, actualError)

	// stop the node
	testNode.Stop()

	// Cannot change the running status of the node to false
	// when its not running
	expError = ErrAlreadyStopped
	actualError = changeRunningStatus(testNode, true, false)
	require.ErrorIs(t, expError, actualError)

	// Should be able to change the running status of the node to true
	// after the node is stopped
	actualError = changeRunningStatus(testNode, false, true)
	require.NoError(t, actualError)
}
