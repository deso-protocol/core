package consensus

import (
	"errors"
	"sync"
	"time"

	"github.com/deso-protocol/core/bls"
)

func NewFastHotStuffConsensus() *FastHotStuffConsensus {
	return &FastHotStuffConsensus{
		status:     consensusStatusNotInitialized,
		startGroup: sync.WaitGroup{},
		stopGroup:  sync.WaitGroup{},
	}
}

// Initializes the consensus instance with the latest known valid block in the blockchain, and
// the validator set for the next block height. The functions expects the following for the input
// params:
//   - blockConstructionCadence: block construction duration must be > 0
//   - timeoutBaseDuration: timeout base duration must be > 0
//   - chainTip: the input block must have a valid block hash, block height, view, and QC
//   - validators: the validators must be sorted in decreasing order of stake, with a
//     consistent tie breaking scheme. The validator set is expected to be valid for
//     validating votes and timeouts for the next block height.
//
// Given the above, This function updates the chain tip internally, and re-initializes all internal
// data structures that are used to track incoming votes and timeout messages for QC construction.
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

// Sets the initial times for the block construction and timeout timers and starts
// the event loop building off of the current chain tip.
func (fc *FastHotStuffConsensus) Start() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is either running or uninitialized.
	// If it's running or uninitialized, then there's nothing to do here.
	if fc.status != consensusStatusInitialized {
		return
	}

	// Set the initial times for the block construction and timeout timers
	fc.nextBlockConstructionTimeStamp = time.Now().Add(fc.blockConstructionCadence)
	fc.nextTimeoutTimeStamp = time.Now().Add(fc.timeoutBaseDuration)

	// Kick off the event loop in a separate goroutine
	go fc.runEventLoop()

	// Wait for the event loop to start
	fc.startGroup.Wait()

	// Update the consensus status to mark it as running.
	fc.status = consensusStatusRunning
}

func (fc *FastHotStuffConsensus) Stop() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Check if the consensus instance is no longer running. If it's not running
	// we can simply return here.
	if fc.status != consensusStatusRunning {
		return
	}

	// Signal the event loop to stop
	fc.stopSignal <- struct{}{}

	// Wait for the event loop to stop
	fc.stopGroup.Wait()

	// Update the consensus status
	fc.status = consensusStatusInitialized

	// Close all internal and external channels used for signaling
	close(fc.internalTimersUpdatedSignal)
	close(fc.stopSignal)
}

// Runs the internal event loop that waits for all internal or external signals. If the
// event loop is running, the consensus instance status must be set to consensusStatusRunning.
// Note, this function does not directly update the consensus status. To simplify the inner
// implementation of the loop, the caller who starts and stops should always be responsible
// for updating the status as it starts and stop the loop.
func (fc *FastHotStuffConsensus) runEventLoop() {
	// Signal that the event loop has started
	fc.startGroup.Done()

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
				// Signal that the event loop has stopped
				fc.stopGroup.Done()
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
