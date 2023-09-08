//go:build relic

package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFastHotStuffInitialization(t *testing.T) {

	// Test initial status for newly constructed instance
	{
		fc := NewFastHotStuffEventLoop()
		require.Equal(t, consensusStatusNotInitialized, fc.status)
		require.NotPanics(t, fc.Stop) // Calling Stop() on an uninitialized instance should be a no-op
	}

	// Test Init() function with invalid block construction cadence
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(0, 1, createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with invalid timeout duration
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 0, createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with malformed block
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 1, nil, createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with malformed validator set
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 1, createDummyBlock(), nil)
		require.Error(t, err)
	}

	// Test Init() function with valid parameters
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(100, 101, createDummyBlock(), createDummyValidatorSet())
		require.NoError(t, err)

		require.Equal(t, consensusStatusInitialized, fc.status)

		require.NotPanics(t, fc.Stop) // Calling Stop() on an initialized instance should be a no-op
		require.Equal(t, fc.status, consensusStatusInitialized)

		require.Equal(t, fc.chainTip.GetBlockHash().GetValue(), createDummyBlockHash().GetValue())
		require.Equal(t, fc.chainTip.GetView(), uint64(1))
		require.Equal(t, fc.chainTip.GetHeight(), uint64(1))

		require.Equal(t, fc.blockConstructionCadence, time.Duration(100))
		require.Equal(t, fc.timeoutBaseDuration, time.Duration(101))

		require.Equal(t, fc.currentView, uint64(2))
		require.Equal(t, len(fc.validatorsAtChainTip), 2)
	}
}

func TestFastHotStuffProcessSafeBlock(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs, createDummyBlock(), createDummyValidatorSet())
	require.NoError(t, err)

	// Test ProcessSafeBlock() function when consensus event loop is not running
	{
		err := fc.ProcessSafeBlock(createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Start the consensus event loop
	fc.Start()

	// Test ProcessSafeBlock() function with malformed block
	{
		err := fc.ProcessSafeBlock(nil, createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test ProcessSafeBlock() function with malformed validator set
	{
		err := fc.ProcessSafeBlock(createDummyBlock(), nil)
		require.Error(t, err)
	}

	// Populate the votesSeen and timeoutsSeen maps with dummy data
	{
		fc.votesSeen = map[[32]byte]map[string]VoteMessage{
			{0}: { // blockHash = 0
				"pubKeyA": createDummyVoteMessage(0),
			},
			{1}: { // blockHash = 1
				"pubKeyB": createDummyVoteMessage(1),
			},
			{2}: { // blockHash = 2
				"pubKeyC": createDummyVoteMessage(2),
			},
			{3}: { // blockHash = 3
				"pubKeyD": createDummyVoteMessage(3),
			},
			{4}: { // blockHash = 4
				"pubKeyE": createDummyVoteMessage(4),
			},
		}

		fc.timeoutsSeen = map[uint64]map[string]TimeoutMessage{
			0: { // view = 0
				"pubKeyA": createDummyTimeoutMessage(0),
			},
			1: { // view = 1
				"pubKeyB": createDummyTimeoutMessage(1),
			},
			2: { // view = 2
				"pubKeyC": createDummyTimeoutMessage(2),
			},
			3: { // view = 3
				"pubKeyD": createDummyTimeoutMessage(3),
			},
			4: { // view = 4
				"pubKeyE": createDummyTimeoutMessage(4),
			},
		}
	}

	// Verify the sizes of the votesSeen and timeoutsSeen maps
	{
		require.Equal(t, len(fc.votesSeen), 5)
		require.Equal(t, len(fc.timeoutsSeen), 5)
	}

	// Test ProcessSafeBlock() function with valid parameters
	{
		nextBlock := createDummyBlock()
		nextBlock.height = 2
		nextBlock.view = 3

		err := fc.ProcessSafeBlock(nextBlock, createDummyValidatorSet())
		require.NoError(t, err)

		require.Equal(t, createDummyBlockHash().GetValue(), fc.chainTip.GetBlockHash().GetValue())
		require.Equal(t, uint64(3), fc.chainTip.GetView())
		require.Equal(t, uint64(2), fc.chainTip.GetHeight())

		require.Equal(t, uint64(4), fc.currentView)
		require.Equal(t, 2, len(fc.validatorsAtChainTip))
	}

	// Verify that stale votes and timeouts have been evicted
	{
		require.Equal(t, 2, len(fc.votesSeen))
		require.Equal(t, 2, len(fc.timeoutsSeen))
	}

	// Stop the event loop
	fc.Stop()
}

func TestFastHotStuffEventLoopStartStop(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)
	tenSecondsInNanoSecs := time.Duration(10000000000)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, 2*oneHourInNanoSecs, createDummyBlock(), createDummyValidatorSet())
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Confirm the consensus instance status has changed to running
	require.Equal(t, consensusStatusRunning, fc.status)

	// Confirm that the ETAs for the block construction and timeout timers have been set
	require.Greater(t, fc.nextBlockConstructionTimeStamp, time.Now().Add(
		oneHourInNanoSecs-tenSecondsInNanoSecs, // Subtract 10 second buffer so this test ins't flaky
	))
	require.Greater(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		2*oneHourInNanoSecs-tenSecondsInNanoSecs, // Subtract 10 second buffer so this test ins't flaky
	))

	// Stop the event loop
	fc.Stop()

	// Confirm the consensus instance status has reverted to initialized
	require.Equal(t, consensusStatusInitialized, fc.status)

	// Confirm that calling fc.Stop() again doesn't panic
	require.NotPanics(t, fc.Stop)
}
