//go:build relic

package consensus

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {

	// Test initial status for newly constructed instance
	{
		fc := NewFastHotStuffEventLoop()
		require.Equal(t, consensusStatusNotInitialized, fc.status)
		require.NotPanics(t, fc.Stop) // Calling Stop() on an uninitialized instance should be a no-op
	}

	// Test Init() function with invalid block construction interval
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(0, 1,
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Test Init() function with invalid timeout duration
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 0,
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Test Init() function with malformed tip block
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 1,
			BlockWithValidators{nil, createDummyValidatorSet()},                     // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Test Init() function with malformed validator set for tip block
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 1,
			BlockWithValidators{createDummyBlock(2), nil},                           // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Test Init() function with malformed safe block
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 1,
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()}, // tip
			[]BlockWithValidators{{nil, createDummyValidatorSet()}},             // safeBlocks
		)
		require.Error(t, err)
	}

	// Test Init() function with malformed validator set for safe block
	{
		fc := NewFastHotStuffEventLoop()
		err := fc.Init(1, 1,
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()}, // tip
			[]BlockWithValidators{{createDummyBlock(2), nil}},                   // safeBlocks
		)
		require.Error(t, err)
	}

	// Test Init() function with valid parameters
	{
		block := createDummyBlock(2)

		fc := NewFastHotStuffEventLoop()
		err := fc.Init(100, 101,
			BlockWithValidators{block, createDummyValidatorSet()},     // tip
			[]BlockWithValidators{{block, createDummyValidatorSet()}}, // safeBlocks
		)
		require.NoError(t, err)

		require.Equal(t, consensusStatusInitialized, fc.status)

		require.NotPanics(t, fc.Stop) // Calling Stop() on an initialized instance should be a no-op
		require.Equal(t, fc.status, consensusStatusInitialized)

		require.Equal(t, fc.tip.block.GetBlockHash().GetValue(), block.GetBlockHash().GetValue())
		require.Equal(t, fc.tip.block.GetView(), uint64(2))
		require.Equal(t, fc.tip.block.GetHeight(), uint64(1))

		require.Equal(t, fc.blockConstructionInterval, time.Duration(100))
		require.Equal(t, fc.timeoutBaseDuration, time.Duration(101))

		require.Equal(t, fc.currentView, uint64(3))
		require.Equal(t, len(fc.tip.validatorSet), 2)
		require.Equal(t, len(fc.tip.validatorLookup), 2)

		require.Equal(t, len(fc.safeBlocks), 1)
		require.Equal(t, fc.safeBlocks[0].block.GetBlockHash().GetValue(), block.GetBlockHash().GetValue())
		require.Equal(t, fc.safeBlocks[0].block.GetView(), uint64(2))
		require.Equal(t, fc.safeBlocks[0].block.GetHeight(), uint64(1))
		require.Equal(t, len(fc.safeBlocks[0].validatorSet), 2)
		require.Equal(t, len(fc.safeBlocks[0].validatorLookup), 2)
	}
}

func TestProcessTipBlock(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs,
		BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
	)
	require.NoError(t, err)

	// Test ProcessTipBlock() function when consensus event loop is not running
	{
		err := fc.ProcessTipBlock(
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Start the consensus event loop
	fc.Start()

	// Test ProcessTipBlock() function with malformed tip block
	{
		err := fc.ProcessTipBlock(
			BlockWithValidators{nil, createDummyValidatorSet()},                     // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Test ProcessTipBlock() function with malformed tip validator set
	{
		err := fc.ProcessTipBlock(
			BlockWithValidators{createDummyBlock(2), nil},                           // tip
			[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
		)
		require.Error(t, err)
	}

	// Test ProcessTipBlock() function with malformed safe block
	{
		err := fc.ProcessTipBlock(
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()}, // tip
			[]BlockWithValidators{{nil, createDummyValidatorSet()}},             // safeBlocks
		)
		require.Error(t, err)
	}

	// Test ProcessTipBlock() function with malformed safe block's validator set
	{
		err := fc.ProcessTipBlock(
			BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()}, // tip
			[]BlockWithValidators{{createDummyBlock(2), nil}},                   // safeBlocks
		)
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

	// Test ProcessTipBlock() function with valid parameters
	{
		nextBlock := createDummyBlock(2)
		nextBlock.height = 2
		nextBlock.view = 3

		err := fc.ProcessTipBlock(
			BlockWithValidators{nextBlock, createDummyValidatorSet()},     // tip
			[]BlockWithValidators{{nextBlock, createDummyValidatorSet()}}, // safeBlocks
		)
		require.NoError(t, err)

		require.Equal(t, nextBlock.GetBlockHash().GetValue(), fc.tip.block.GetBlockHash().GetValue())
		require.Equal(t, uint64(3), fc.tip.block.GetView())
		require.Equal(t, uint64(2), fc.tip.block.GetHeight())

		require.Equal(t, uint64(4), fc.currentView)
		require.Equal(t, 2, len(fc.tip.validatorSet))
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

	// BlockHeight = 1, Current View = 3
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs,
		BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
	)
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
			{1}: { // blockHash = 1
				"pubKeyA": createDummyVoteMessage(1),
			},
			{2}: { // blockHash = 2
				"pubKeyB": createDummyVoteMessage(2),
			},
			{3}: { // blockHash = 3
				"pubKeyC": createDummyVoteMessage(3),
			},
			{4}: { // blockHash = 4
				"pubKeyD": createDummyVoteMessage(4),
			},
			{5}: { // blockHash = 5
				"pubKeyE": createDummyVoteMessage(5),
			},
		}

		fc.timeoutsSeen = map[uint64]map[string]TimeoutMessage{
			1: { // view = 1
				"pubKeyA": createDummyTimeoutMessage(1),
			},
			2: { // view = 2
				"pubKeyB": createDummyTimeoutMessage(2),
			},
			3: { // view = 3
				"pubKeyC": createDummyTimeoutMessage(3),
			},
			4: { // view = 4
				"pubKeyD": createDummyTimeoutMessage(4),
			},
			5: { // view = 5
				"pubKeyE": createDummyTimeoutMessage(5),
			},
		}
	}

	// Run AdvanceView() to view 4
	{
		newView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(4), newView)
	}

	// Verify that vote and timeout messages haven't changed
	{
		require.Equal(t, len(fc.votesSeen), 3)
		require.Equal(t, len(fc.timeoutsSeen), 3)
	}

	// Run AdvanceView() to view 5
	{
		newView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(5), newView)
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

	// BlockHeight = 1, Current View = 3
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs,
		BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
	)
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Current View = 4
	{
		currentView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(4), currentView)
	}

	// Test with malformed vote
	{
		err := fc.ProcessValidatorVote(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Malformed vote message")
	}

	// Test invalid signature
	{
		vote := createDummyVoteMessage(4)
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
		vote := createDummyVoteMessage(4)
		fc.votesSeen[GetVoteSignaturePayload(vote.GetView(), vote.GetBlockHash())] = map[string]VoteMessage{
			vote.publicKey.ToString(): vote,
		}

		err := fc.ProcessValidatorVote(vote)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already voted for view")
	}

	// Test when we've already seen a timeout from the validator for the same view
	{
		vote := createDummyVoteMessage(5)
		timeout := createDummyTimeoutMessage(5)
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
		vote := createDummyVoteMessage(4)
		err := fc.ProcessValidatorVote(vote)
		require.NoError(t, err)
	}

	// Stop the event loop
	fc.Stop()
}

func TestProcessValidatorTimeout(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()

	// BlockHeight = 1, Current View = 3
	err := fc.Init(oneHourInNanoSecs, oneHourInNanoSecs,
		BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
	)
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Current View = 4
	{
		currentView, err := fc.AdvanceView()
		require.NoError(t, err)
		require.Equal(t, uint64(4), currentView)
	}

	// Test with malformed timeout
	{
		err := fc.ProcessValidatorTimeout(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Malformed timeout message")
	}

	// Test invalid signature
	{
		timeout := createDummyTimeoutMessage(4)
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
		timeout := createDummyTimeoutMessage(4)
		vote := createDummyVoteMessage(4)

		fc.votesSeen[GetVoteSignaturePayload(vote.GetView(), vote.GetBlockHash())] = map[string]VoteMessage{
			timeout.publicKey.ToString(): vote,
		}

		err = fc.ProcessValidatorTimeout(timeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already voted for view")
	}

	// Test when we've already seen a timeout from the validator for the same view
	{
		timeout := createDummyTimeoutMessage(4)

		fc.timeoutsSeen[timeout.view] = map[string]TimeoutMessage{
			timeout.publicKey.ToString(): timeout,
		}

		err = fc.ProcessValidatorTimeout(timeout)
		require.Error(t, err)
		require.Contains(t, err.Error(), "has already timed out for view")
	}

	// Test happy path
	{
		timeout := createDummyTimeoutMessage(4)
		err := fc.ProcessValidatorTimeout(timeout)
		require.NoError(t, err)
	}

	// Stop the event loop
	fc.Stop()
}

func TestTimeoutScheduledTaskExecuted(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)
	oneMilliSecondInNanoSeconds := time.Duration(1000000)

	dummyBlock := createDummyBlock(2)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, oneMilliSecondInNanoSeconds,
		BlockWithValidators{dummyBlock, createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{dummyBlock, createDummyValidatorSet()}}, // safeBlocks
	)
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Wait for the timeout signal to be sent
	timeoutSignal := <-fc.ConsensusEvents

	// Confirm that the timeout signal is for the the expected view
	require.Equal(t, timeoutSignal.EventType, ConsensusEventTypeTimeout)
	require.Equal(t, timeoutSignal.View, dummyBlock.GetView()+1)
	require.Equal(t, timeoutSignal.BlockHash.GetValue(), dummyBlock.GetBlockHash().GetValue())

	// Confirm that the timeout is no longer running
	require.False(t, fc.nextTimeoutTask.IsScheduled())

	// Advance the view, which should reset the timeout scheduled task
	fc.AdvanceView()

	// Wait for the timeout signal to be sent
	timeoutSignal = <-fc.ConsensusEvents

	// Confirm that the timeout signal is for the the expected view
	require.Equal(t, timeoutSignal.EventType, ConsensusEventTypeTimeout)
	require.Equal(t, timeoutSignal.View, dummyBlock.GetView()+2)
	require.Equal(t, timeoutSignal.BlockHash.GetValue(), dummyBlock.GetBlockHash().GetValue())

	// Confirm that the timeout is no longer running
	require.False(t, fc.nextTimeoutTask.IsScheduled())

	// Stop the event loop
	fc.Stop()
}

func TestResetEventLoopSignal(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, 2*oneHourInNanoSecs,
		BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
	)
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Confirm the ETAs for the block construction and timeout timers
	require.Equal(t, fc.nextBlockConstructionTask.GetDuration(), oneHourInNanoSecs) // 1 hour away
	require.Equal(t, fc.nextTimeoutTask.GetDuration(), 2*oneHourInNanoSecs)         // 2 hours away

	// Advance the view to simulate a timeout
	_, err = fc.AdvanceView()
	require.NoError(t, err)

	// Confirm the ETAs for the block construction and timeout timers
	require.Equal(t, fc.nextBlockConstructionTask.GetDuration(), oneHourInNanoSecs) // 1 hour away
	require.Equal(t, fc.nextTimeoutTask.GetDuration(), 4*oneHourInNanoSecs)         // 2 hours * 2 = 4 hours away

	// Advance the view to simulate a 2nd timeout
	_, err = fc.AdvanceView()
	require.NoError(t, err)

	// Confirm the ETAs for the block construction and timeout timers
	require.Equal(t, fc.nextBlockConstructionTask.GetDuration(), oneHourInNanoSecs) // 1 hour away
	require.Equal(t, fc.nextTimeoutTask.GetDuration(), 8*oneHourInNanoSecs)         // 2 hours * 2^2 = 8 hours away

	// Advance the view to simulate a 3nd timeout
	_, err = fc.AdvanceView()
	require.NoError(t, err)

	// Confirm the ETAs for the block construction and timeout timers
	require.Equal(t, fc.nextBlockConstructionTask.GetDuration(), oneHourInNanoSecs) // 1 hour away
	require.Equal(t, fc.nextTimeoutTask.GetDuration(), 16*oneHourInNanoSecs)        // 2 hours * 2^3 = 16 hours away

	// Stop the event loop
	fc.Stop()
}

func TestFastHotStuffEventLoopStartStop(t *testing.T) {
	oneHourInNanoSecs := time.Duration(3600000000000)

	fc := NewFastHotStuffEventLoop()
	err := fc.Init(oneHourInNanoSecs, 2*oneHourInNanoSecs,
		BlockWithValidators{createDummyBlock(2), createDummyValidatorSet()},     // tip
		[]BlockWithValidators{{createDummyBlock(2), createDummyValidatorSet()}}, // safeBlocks
	)
	require.NoError(t, err)

	// Start the event loop
	fc.Start()

	// Confirm the consensus instance status has changed to running
	require.Equal(t, consensusStatusRunning, fc.status)

	// Confirm that the ETAs for the block construction and timeout timers have been set
	require.Equal(t, fc.nextBlockConstructionTask.GetDuration(), oneHourInNanoSecs)
	require.Equal(t, fc.nextTimeoutTask.GetDuration(), 2*oneHourInNanoSecs)

	// Stop the event loop
	fc.Stop()

	// Confirm the consensus instance status has reverted to initialized
	require.Equal(t, consensusStatusInitialized, fc.status)

	// Confirm that calling fc.Stop() again doesn't panic
	require.NotPanics(t, fc.Stop)
}
