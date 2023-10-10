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

func (fc *FastHotStuffConsensus) Init( /*TODO */) {
	// TODO
}

func (fc *FastHotStuffConsensus) HandleAcceptedBlock( /* TODO */) {
	// TODO
}

func (fc *FastHotStuffConsensus) HandleVoteMessage( /* TODO */) {
	// TODO
}

func (pc *FastHotStuffConsensus) HandleTimeoutMessage( /* TODO */) {
	// TODO
}

func (fc *FastHotStuffConsensus) HandleBlockProposal( /* TODO */) {
	// TODO
}

func (fc *FastHotStuffConsensus) Start() {
	for {
		select {
		case <-time.After(time.Until(fc.nextBlockProposalTime)):
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
				close(fc.quit)
				return
			}
		}
	}
}

func (fc *FastHotStuffConsensus) Stop() {
	fc.quit <- struct{}{}
}
