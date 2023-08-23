package consensus

import (
	"errors"
	"time"

	"github.com/deso-protocol/core/bls"
)

func NewFastHotStuffConsensus() *FastHotStuffConsensus {
	return &FastHotStuffConsensus{
		status: consensusStatusNotRunning,
	}
}

// Initializes the consensus instance with the latest known valid block in the blockchain, and
// the validator set. The functions expects the following for the input params:
//   - Block construction duration must be > 0
//   - Timeout base duration must be > 0
//   - The input block must have a valid block hash, block height, view, and QC
//   - The validators param must be sorted in decreasing order of stake, with a
//     consistent tie breaking scheme. The validator set is expected to be valid for
//     validating votes and timeouts for the next block height.
//
// Given the above, This function does two things:
//   - Initializes all internal data structures so used to track incoming votes and timeout messages
//   - Starts the internal timers that regulate consensus timeouts and the block proposal
//     crank timer.
func (fc *FastHotStuffConsensus) Init(
	blockConstructionCadence time.Duration,
	timeoutBaseDuration time.Duration,
	chainTip Block,
	validators []Validator,
) error {
	// Grab the instance's lock
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Ensure the consensus instance is not already running
	if fc.status != consensusStatusRunning {
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
	fc.internalTimersUpdated = make(chan interface{})
	fc.stop = make(chan interface{})
	fc.ConsensusEvents = make(chan *ConsensusEvent)

	// Set the block construction and timeout base durations
	fc.blockConstructionCadence = blockConstructionCadence
	fc.timeoutBaseDuration = timeoutBaseDuration

	// Start the crank and timeout timers
	fc.nextBlockConstructionTime = time.Now().Add(blockConstructionCadence)
	fc.nextTimeoutTime = time.Now().Add(timeoutBaseDuration)

	// Update the consensus status
	fc.status = consensusStatusRunning

	// Start the consensus internal event loop
	go fc.runEventLoop()

	return nil
}

func (fc *FastHotStuffConsensus) IsRunning() bool {
	fc.lock.RLock()
	defer fc.lock.RUnlock()

	return fc.status == consensusStatusRunning
}

func (fc *FastHotStuffConsensus) Stop() {
	fc.stop <- struct{}{}
}

func (fc *FastHotStuffConsensus) UpdateChainTip( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) HandleVoteMessage( /* TODO */ ) {
	// TODO
}

func (pc *FastHotStuffConsensus) HandleTimeoutMessage( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) ConstructVoteQC( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) ConstructTimeoutQC( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) onStopInternalSignal() {
	fc.lock.Lock()
	defer fc.lock.Unlock()

	// Reset all internal and external channels used for signaling
	fc.internalTimersUpdated = make(chan interface{})
	fc.stop = make(chan interface{})

	// Update the consensus status
	fc.status = consensusStatusNotRunning
}

func (fc *FastHotStuffConsensus) runEventLoop() {
	for {
		select {
		case <-time.After(time.Until(fc.nextBlockConstructionTime)):
			{
				// TODO
			}
		case <-time.After(time.Until(fc.nextTimeoutTime)):
			{
				// TODO
			}
		case <-fc.internalTimersUpdated:
			{
				// TODO
			}
		case <-fc.stop:
			{
				fc.onStopInternalSignal()
				return
			}
		}
	}
}
