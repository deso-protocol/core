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

func TestAdvanceView(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()

	// BlockHeight = 1, Current View = 2
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs, createDummyBlock(), createDummyValidatorSet())
	require.NoError(t, err)

	// Running AdvanceView() should fail because the consensus event loop is not running
	{
		_, err := fc.AdvanceView()
		require.Error(t, err)
	}

	// Start the consensus event loop
	fc.Start()

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

	// Run AdvanceView() to view 3
	{
		newView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(3), newView)
	}

	// Verify that vote and timeout messages haven't changed
	{
		require.Equal(t, len(fc.votesSeen), 3)
		require.Equal(t, len(fc.timeoutsSeen), 3)
	}

	// Run AdvanceView() to view 4
	{
		newView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(4), newView)
	}

	// Verify that stale votes and timeouts have been evicted
	{
		require.Equal(t, len(fc.votesSeen), 2)
		require.Equal(t, len(fc.timeoutsSeen), 2)
	}

	// Stop the event loop
	fc.Stop()
}

func TestProcessValidatorVote(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()

	// BlockHeight = 1, Current View = 2
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs, createDummyBlock(), createDummyValidatorSet())
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Current View = 3
	{
		currentView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(3), currentView)
	}

	// Test with malformed vote
	{
		err := fc.ProcessValidatorVote(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Malformed vote message")
	}

	// Test invalid signature
	{
		vote := createDummyVoteMessage(3)
		vote.signature = createDummyBLSSignature()
		err := fc.ProcessValidatorVote(vote)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Invalid signature")
	}

	// Test with stale view
	{
		vote := createDummyVoteMessage(1)
		err := fc.ProcessValidatorVote(vote)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Vote has a stale view")
	}

	// Test when we've already seen a vote from the validator for the same view
	{
		vote := createDummyVoteMessage(3)
		fc.votesSeen[GetVoteSignaturePayload(vote.GetView(), vote.GetBlockHash())] = map[string]VoteMessage{
			vote.publicKey.ToString(): vote,
		}

		err := fc.ProcessValidatorVote(vote)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already voted for view")
	}

	// Test when we've already seen a timeout from the validator for the same view
	{
		vote := createDummyVoteMessage(4)
		timeout := createDummyTimeoutMessage(4)
		timeout.publicKey = vote.publicKey

		fc.timeoutsSeen[timeout.GetView()] = map[string]TimeoutMessage{
			timeout.publicKey.ToString(): timeout,
		}

		err := fc.ProcessValidatorVote(vote)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already timed out for view")
	}

	// Test happy path
	{
		vote := createDummyVoteMessage(3)
		err := fc.ProcessValidatorVote(vote)
		require.NoError(t, err)
	}

	// Stop the event loop
	fc.Stop()
}

func TestProcessValidatorTimeout(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()

	// BlockHeight = 1, Current View = 2
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs, createDummyBlock(), createDummyValidatorSet())
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Current View = 3
	{
		currentView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(3), currentView)
	}

	// Test with malformed timeout
	{
		err := fc.ProcessValidatorTimeout(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Malformed timeout message")
	}

	// Test invalid signature
	{
		timeout := createDummyTimeoutMessage(3)
		timeout.signature = createDummyBLSSignature()
		err := fc.ProcessValidatorTimeout(timeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Invalid signature")
	}

	// Test with stale view
	{
		timeout := createDummyTimeoutMessage(1)
		err := fc.ProcessValidatorTimeout(timeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Timeout has a stale view")
	}

	// Test when we've already seen a vote from the validator for the same view
	{
		timeout := createDummyTimeoutMessage(3)
		vote := createDummyVoteMessage(3)

		fc.votesSeen[GetVoteSignaturePayload(vote.GetView(), vote.GetBlockHash())] = map[string]VoteMessage{
			timeout.publicKey.ToString(): vote,
		}

		err = fc.ProcessValidatorTimeout(timeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already voted for view")
	}

	// Test when we've already seen a timeout from the validator for the same view
	{
		timeout := createDummyTimeoutMessage(3)

		fc.timeoutsSeen[timeout.view] = map[string]TimeoutMessage{
			timeout.publicKey.ToString(): timeout,
		}

		err = fc.ProcessValidatorTimeout(timeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already timed out for view")
	}

	// Test happy path
	{
		timeout := createDummyTimeoutMessage(3)
		err := fc.ProcessValidatorTimeout(timeout)
		require.NoError(t, err)
	}

	// Stop the event loop
	fc.Stop()
}

func TestResetEventLoopSignal(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)
	tenSecondsInNanoSecs := time.Duration(10000000000)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, 2*oneHourInNanoSecs, createDummyBlock(), createDummyValidatorSet())
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Confirm the ETAs for the block construction and timeout timers
	require.Greater(t, fc.nextBlockConstructionTimeStamp, time.Now().Add(
		oneHourInNanoSecs-tenSecondsInNanoSecs, // 1 hour away
	))
	require.Greater(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		2*oneHourInNanoSecs-tenSecondsInNanoSecs, // 2 hours = 4 hours away
	))
	require.Less(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		2*oneHourInNanoSecs+tenSecondsInNanoSecs, // 2 hours = 4 hours away
	))

	// Advance the view to simulate a timeout
	_, err = fc.AdvanceView()
	require.NoError(t, err)

	// Confirm the ETAs for the block construction and timeout timers
	require.Greater(t, fc.nextBlockConstructionTimeStamp, time.Now().Add(
		oneHourInNanoSecs-tenSecondsInNanoSecs, // 1 hour away
	))
	require.Greater(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		4*oneHourInNanoSecs-tenSecondsInNanoSecs, // 2 hours * 2 = 4 hours away
	))
	require.Less(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		4*oneHourInNanoSecs+tenSecondsInNanoSecs, // 2 hours * 2 = 4 hours away
	))

	// Advance the view to simulate a 2nd timeout
	_, err = fc.AdvanceView()
	require.NoError(t, err)

	// Confirm the ETAs for the block construction and timeout timers
	require.Greater(t, fc.nextBlockConstructionTimeStamp, time.Now().Add(
		oneHourInNanoSecs-tenSecondsInNanoSecs, // 1 hour away
	))
	require.Greater(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		8*oneHourInNanoSecs-tenSecondsInNanoSecs, // 2 hours * 2^2 = 8 hours away
	))
	require.Less(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		8*oneHourInNanoSecs+tenSecondsInNanoSecs, // 2 hours * 2 = 8 hours away
	))

	// Advance the view to simulate a 3nd timeout
	_, err = fc.AdvanceView()
	require.NoError(t, err)

	// Confirm the ETAs for the block construction and timeout timers
	require.Greater(t, fc.nextBlockConstructionTimeStamp, time.Now().Add(
		oneHourInNanoSecs-tenSecondsInNanoSecs, // 1 hour away
	))
	require.Greater(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		16*oneHourInNanoSecs-tenSecondsInNanoSecs, // 2 hours * 2^3 = 16 hours away
	))
	require.Less(t, fc.nextTimeoutTimeStamp, time.Now().Add(
		16*oneHourInNanoSecs+tenSecondsInNanoSecs, // 2 hours * 2^3 = 16 hours away
	))

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