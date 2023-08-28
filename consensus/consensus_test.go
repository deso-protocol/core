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
		fc := NewFastHotStuffConsensus()
		require.Equal(t, consensusStatusNotInitialized, fc.status)
		require.Equal(t, fc.IsInitialized(), false)
		require.Equal(t, fc.IsRunning(), false)
		require.NotPanics(t, fc.Stop) // Calling Stop() on an uninitialized instance should be a no-op
	}

	// Test Init() function with invalid block construction cadence
	{
		fc := NewFastHotStuffConsensus()
		err := fc.Init(0, 1, createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with invalid timeout duration
	{
		fc := NewFastHotStuffConsensus()
		err := fc.Init(1, 0, createDummyBlock(), createDummyValidatorSet())
		require.Error(t, err)
	}

	// Test Init() function with valid parameters
	{
		fc := NewFastHotStuffConsensus()
		err := fc.Init(100, 101, createDummyBlock(), createDummyValidatorSet())
		require.NoError(t, err)

		require.Equal(t, consensusStatusInitialized, fc.status)
		require.Equal(t, fc.IsInitialized(), true)
		require.Equal(t, fc.IsRunning(), false)

		require.NotPanics(t, fc.Stop) // Calling Stop() on an initialized instance should be a no-op
		require.Equal(t, fc.status, consensusStatusInitialized)

		require.Equal(t, fc.chainTip.GetBlockHash().GetValue(), createDummyBlockHash().GetValue())
		require.Equal(t, fc.chainTip.GetView(), uint64(0))
		require.Equal(t, fc.chainTip.GetHeight(), uint64(0))

		require.Equal(t, fc.blockConstructionCadence, time.Duration(100))
		require.Equal(t, fc.timeoutBaseDuration, time.Duration(101))

		require.Equal(t, fc.currentView, uint64(1))
		require.Equal(t, len(fc.validators), len(createDummyValidatorSet()))
	}
}

func TestFastHotStuffEventLoopStartStop(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)
	tenSecondsInNanoSecs := time.Duration(10000000000)

	fc := NewFastHotStuffConsensus()
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
