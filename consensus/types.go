package consensus

import (
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
)

// ConsensusEvent is a way for FastHotStuffConsensus to send messages back to
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
	BlockHash   BlockHash
	BlockHeight uint64
	View        uint64
}

// BlockHash is a 32-byte hash of a block used to uniquely identify a block. It's re-defined here
// to match the exact structure of the BlockHash type in core, so the two packages are decoupled and
// the Fast HotStuff consensus can be tested end-to-end independently. When using the Fast HotStuff,
// the lib package can convert its own BlockHash type to and from this type trivially.
type BlockHash interface {
	GetValue() [32]byte
}

type Validator interface {
	GetPublicKey() bls.PublicKey
	GetStakeAmount() *uint256.Int
}

type Vote interface {
	GetView()
	GetBlockHash() BlockHash

	GetPublicKey() bls.PublicKey
	GetSignature() bls.Signature
}

type Timeout interface {
	GetView() uint64
	GetHighQC() QuorumCertificate

	GetPublicKey() bls.PublicKey
	GetSignature() bls.Signature
}

type Block interface {
	GetBlockHash() BlockHash
	GetHeight() uint64
	GetView() uint64
	// This is a hybrid function that returns the QC from the block.
	// - If the block is a normal block, this returns the validators' votes for the previous block
	// - If the block contains a timeout QC, this returns the validators' high QC aggregated from
	//   validators' timeout messages
	// We are able to simplify this getter function QC getter for this block interface because this
	// consensus engine does not validate QCs on incoming blocks.
	GetQC() QuorumCertificate
}

type QuorumCertificate interface {
	GetBlockHash() BlockHash
	GetView() uint64
	GetSignersList() *bitset.Bitset
	GetAggregatedSignature() *bls.Signature
}

// An instance of FastHotStuffConsensus is a self-contained engine that runs the Fast HotStuff consensus
// protocol, and signals the Server whenever it's ready to perform an action. This engine always builds
// off of the latest block accepted and validated by the server. It always expects the server to have
// validated and connected an incoming block before calling UpdateChainTip(). This assumption allows
// us to simplify the role of the engine to strictly run the crank & timeout timers; to track incoming
// votes & timeout messages; and to signal when it is ready to take action for the next vote, timeout,
// and block construction.
type FastHotStuffConsensus struct {
	blockConstructionDuration time.Duration
	timeoutBaseDuration       time.Duration

	nextBlockConstructionTime time.Time
	nextTimeoutTime           time.Time

	// The latest block accepted by the server. We only keep track of and build on top of the the chain
	// tip here. In the event of a fork, we expect the new tip to be resolved externally and passed in.
	chainTip Block
	// The expected view for the next block. In the event of a timeout, the timeout signal will be triggered
	// for this view.
	nextView uint64
	// The validator set sorted in decreasing order of stake amount, with a consistent tie-breaking
	// scheme.
	validators []Validator

	// votesSeen and timeoutsSeen are in-memory maps of all the votes and timeouts we've
	// seen so far, organized by their block hash and then by the public key of the voter.
	votesSeen    map[BlockHash]map[bls.PublicKey]*bls.Signature // TODO: this should be a vote message
	timeoutsSeen map[BlockHash]map[bls.PublicKey]*bls.Signature // TODO: this should be a timeout message

	// Externally accessible channel for signals sent to the server.
	ConsensusEvents chan *ConsensusEvent

	// Internal signals used by the engine to update & reset state.
	internalTimersUpdated chan interface{}
	quit                  chan interface{}
}
