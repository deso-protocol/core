package consensus

import (
	"errors"
	"time"

	"github.com/deso-protocol/core/bls"
)

func NewFastHotStuffConsensus() *FastHotStuffConsensus {
	return &FastHotStuffConsensus{
		status: consensusStatusNotInitialized,
	}
}

// Initializes the consensus instance with the latest known valid block in the blockchain, and
// the validator set for the next block height. The functions expects the following for the input
// params:
//   - Block construction duration must be > 0
//   - Timeout base duration must be > 0
//   - The input block must have a valid block hash, block height, view, and QC
//   - The validators param must be sorted in decreasing order of stake, with a
//     consistent tie breaking scheme. The validator set is expected to be valid for
//     validating votes and timeouts for the next block height.
//
// Given the above, This function updates the chain tip internally, and initializes all internal
// data structures that are used to track incoming votes and timeout messages.
func (fc *FastHotStuffConsensus) Init(
	blockConstructionCadence time.Duration,
	timeoutBaseDuration time.Duration,
	chainTip Block,
	validators []Validator,
) error {
	// Grab the consensus instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is not already running
	if fc.status == consensusStatusRunning {
		return errors.New("Consensus instance is already running")
	}

	// Validate the inputs
	if blockConstructionCadence <= 0 {
		return errors.New("Block construction duration must be > 0")
	}
	if timeoutBaseDuration <= 0 {
		return errors.New("Timeout base duration must be > 0")
	}

	// Update the chain tip and validator set
	fc.chainTip = chainTip
	fc.currentView = chainTip.GetView() + 1
	fc.validators = validators

	// Reset all internal data structures for votes and timeouts
	fc.votesSeen = make(map[BlockHash]map[bls.PublicKey]VoteMessage)
	fc.timeoutsSeen = make(map[uint64]map[bls.PublicKey]TimeoutMessage)

	// Reset all internal and external channels used for signaling
	fc.internalTimersUpdatedSignal = make(chan interface{})
	fc.stopSignal = make(chan interface{})
	fc.ConsensusEvents = make(chan *ConsensusEvent)

	// Set the block construction and timeout base durations
	fc.blockConstructionCadence = blockConstructionCadence
	fc.timeoutBaseDuration = timeoutBaseDuration

	// Update the consensus status
	fc.status = consensusStatusInitialized

	return nil
}

func (fc *FastHotStuffConsensus) UpdateChainTip( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) UpdateView( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) ProcessVoteMsg( /* TODO */ ) {
	// TODO
}

func (pc *FastHotStuffConsensus) ProcessTimeoutMsg( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) ConstructVoteQC( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) ConstructTimeoutQC( /* TODO */ ) {
	// TODO
}

// Sets the initial times for the the block construction and timeout timers and starts
// the event loop building off of the current chain tip.
func (fc *FastHotStuffConsensus) Start() {
	fc.lock.Lock()
	if fc.status != consensusStatusInitialized {
		// Nothing to do here. The consensus instance is either already running or uninitialized.
		fc.lock.Unlock()
		return
	}

	// Update the consensus status to mark it as running.
	fc.status = consensusStatusRunning

	// Set the initial times for the the block construction and timeout timers
	fc.nextBlockConstructionTimeStamp = time.Now().Add(fc.blockConstructionCadence)
	fc.nextTimeoutTimeStamp = time.Now().Add(fc.timeoutBaseDuration)

	// We can release the lock now that all state changes has been set up to start
	// the event loop.
	fc.lock.Unlock()

	// Start the event loop
	for {
		select {
		case <-time.After(time.Until(fc.nextBlockConstructionTimeStamp)):
			{
				// TODO
			}
		case <-time.After(time.Until(fc.nextTimeoutTimeStamp)):
			{
				// TODO
			}
		case <-fc.internalTimersUpdatedSignal:
			{
				// TODO
			}
		case <-fc.stopSignal:
			{
				fc.onStopSignal()
				return
			}
		}
	}
}

func (fc *FastHotStuffConsensus) IsInitialized() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status != consensusStatusNotInitialized
}

func (fc *FastHotStuffConsensus) IsRunning() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status == consensusStatusRunning
}

func (fc *FastHotStuffConsensus) Stop() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Grabbing the lock first and checking the status ensures that we can never push a stop
	// signal once the channel has been closed. It's OK if we push multiple stop signals while
	// the channel is still open.
	if fc.status == consensusStatusRunning {
		fc.stopSignal <- struct{}{}
	}
}

func (fc *FastHotStuffConsensus) onStopSignal() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Close all internal and external channels used for signaling
	close(fc.internalTimersUpdatedSignal)
	close(fc.stopSignal)

	// Update the consensus status
	fc.status = consensusStatusInitialized
}
