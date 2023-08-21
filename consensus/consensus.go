package consensus

import (
	"time"

	"github.com/deso-protocol/core/bls"
)

func NewFastHotStuffConsensus() *FastHotStuffConsensus {
	return &FastHotStuffConsensus{
		internalTimersUpdated: make(chan interface{}),
		votesSeen:             make(map[BlockHash]map[bls.PublicKey]*bls.Signature),
		timeoutsSeen:          make(map[BlockHash]map[bls.PublicKey]*bls.Signature),
		ConsensusEvents:       make(chan *ConsensusEvent),
	}
}

// Initializes the consensus engine with the latest known valid block in the blockchain, and
// the validator set. The functions expects the following for the input params:
//   - Block construction duration must be > 0
//   - Timeout base duration must be > 0
//   - The input block must have a valid block hash, block height, view, and QC
//   - The validators param must be sorted in decreasing order of stake, with a
//     consistent tie breaking scheme. The validator set is expected to be valid for
//     validating votes and timeouts for the next block height.
//
// Given the above, This function does two things:
//   - Initializes all internal data structures so that the engine can begin tracking
//     incoming votes and timeout messages
//   - Starts the internal timers that regulate consensus timeouts and the block proposal
//     crank timer.
func (fc *FastHotStuffConsensus) Init(
	blockConstructionDuration time.Duration,
	timeoutBaseDuration time.Duration,
	chainTip Block,
	validators []Validator,
) error {
	// TODO: validate the inputs

	// Initialize the chain tip and validator set
	fc.chainTip = chainTip
	fc.nextView = chainTip.GetView() + 1
	fc.validators = validators

	// Reset all internal data structures
	fc.votesSeen = make(map[BlockHash]map[bls.PublicKey]*bls.Signature)
	fc.timeoutsSeen = make(map[BlockHash]map[bls.PublicKey]*bls.Signature)

	// Reset all internal and external channels
	fc.internalTimersUpdated = make(chan interface{})
	fc.quit = make(chan interface{})
	fc.ConsensusEvents = make(chan *ConsensusEvent)

	// Start the crank and timeout timers
	fc.nextBlockConstructionTime = time.Now().Add(blockConstructionDuration)
	fc.nextTimeoutTime = time.Now().Add(timeoutBaseDuration)
	go fc.start()
}

func (fc *FastHotStuffConsensus) HandleAcceptedBlock( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) HandleVoteMessage( /* TODO */ ) {
	// TODO
}

func (pc *FastHotStuffConsensus) HandleTimeoutMessage( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) ConstructNextBlockQC( /* TODO */ ) {
	// TODO
}

func (fc *FastHotStuffConsensus) start() {
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
		case <-fc.quit:
			{
				// TODO
				return
			}
		}
	}
}

func (fc *FastHotStuffConsensus) Stop() {
	fc.quit <- struct{}{}
}
