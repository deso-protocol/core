package consensus

import (
	"time"

	"github.com/deso-protocol/core/bls"
)

// ConsensusEvent is a way for NewFastHotStuffConsensus to send messages back to
// the Server. There are three types of events that can be sent:
//   - Vote: The consensus is ready to vote on a block
//   - Timeout: The consensus has timed out on a view
//   - BlockProposal: The consensus has a QC for a block and is ready to propose the next
//     block

type ConsensusEventType byte

const (
	ConsensusEventTypeTimeout ConsensusEventType = iota
	ConsensusEventTypeBlockProposal
	ConsensusEventTypeVote
)

type ConsensusEvent struct {
	EventType   ConsensusEventType
	BlockHeight uint64
	View        uint64
}

// BlockHash is a 32-byte hash of a block used to uniquely identify a block. It's re-defined here
// to match the exact structure of the BlockHash type in core, so the two packages are decoupled and
// the Fast HotStuff consensus can be tested end-to-end independently. When using the Fast HotStuff,
// the lib package can convert its own BlockHash type to and from this type trivially.
type BlockHash [32]byte

// NewFastHotStuffConsensus creates a new persistent FastHotStuffConsensus object that internally
// runs the Fast HotStuff consensus protocol, and signals the Server whenever it's ready to perform
// an action.

type FastHotStuffConsensus struct {
	nextBlockProposalTime time.Time
	nextTimeoutTime       time.Time

	internalTimersUpdated chan interface{}
	quit                  chan interface{}

	// votesSeen and timeoutsSeen are in-memory maps of all the votes and timeouts we've
	// seen so far, organized by their block hash and then by the public key of the voter.
	votesSeen    map[BlockHash]map[bls.PublicKey]*bls.Signature // TODO: this should be a vote message
	timeoutsSeen map[BlockHash]map[bls.PublicKey]*bls.Signature // TODO: this should be a timeout message

	ConsensusEvents chan *ConsensusEvent
}
