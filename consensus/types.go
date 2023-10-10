package consensus

import (
	"sync"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
)

// FastHotStuffEventType is a way for FastHotStuffEventLoop to send messages back to the Server.
// There are four types of events that can be sent:
//   - FastHotStuffEventTypeVote: The event loop is ready to vote on a block at a given block height and view
//   - FastHotStuffEventTypeTimeout: The event loop has timed out on a view
//   - FastHotStuffEventTypeConstructVoteQC: The event loop has a QC for a block and is ready to construct the
//     next block at the next block height and the current view
//   - FastHotStuffEventTypeConstructTimeoutQC: The event loop has a timeout QC for a view and is ready to
//     construct an empty block with the timeout QC at the next block height and the current view

type FastHotStuffEventType byte

const (
	FastHotStuffEventTypeVote               FastHotStuffEventType = 0
	FastHotStuffEventTypeTimeout            FastHotStuffEventType = 1
	FastHotStuffEventTypeConstructVoteQC    FastHotStuffEventType = 2
	FastHotStuffEventTypeConstructTimeoutQC FastHotStuffEventType = 3
)

type FastHotStuffEvent struct {
	EventType      FastHotStuffEventType
	TipBlockHash   BlockHash
	TipBlockHeight uint64
	View           uint64
	QC             QuorumCertificate
	AggregateQC    AggregateQuorumCertificate
}

// BlockHash is a 32-byte hash of a block used to uniquely identify a block. It's re-defined here
// as an interface that matches the exact structure of the BlockHash type in core, so that the two
// packages are decoupled and the Fast HotStuff event loop can be tested end-to-end independently.
// When using the Fast HotStuff event loop, the lib package can convert its own BlockHash type to
// and from this type trivially.
type BlockHash interface {
	GetValue() [32]byte
}

type Validator interface {
	GetPublicKey() *bls.PublicKey
	GetStakeAmount() *uint256.Int
}

type AggregateQuorumCertificate interface {
	GetView() uint64
	GetHighQC() QuorumCertificate
	GetHighQCViews() []uint64
	GetAggregatedSignature() AggregatedSignature
}

type QuorumCertificate interface {
	GetBlockHash() BlockHash
	GetView() uint64
	GetAggregatedSignature() AggregatedSignature
}

type AggregatedSignature interface {
	GetSignersList() *bitset.Bitset
	GetSignature() *bls.Signature
}

type VoteMessage interface {
	GetView() uint64
	GetBlockHash() BlockHash

	GetPublicKey() *bls.PublicKey

	// The validator's BLS signature of the (View, BlockHash) pair. This represents the validator's
	// vote for this block. The block height is implicitly captured in the block hash.
	GetSignature() *bls.Signature
}

type TimeoutMessage interface {
	GetView() uint64
	GetHighQC() QuorumCertificate

	GetPublicKey() *bls.PublicKey
	// The validator's BLS signature of the (View, HighQC.View) pair.
	GetSignature() *bls.Signature
}

type Block interface {
	GetBlockHash() BlockHash
	GetHeight() uint64
	GetView() uint64
	// This is a hybrid function that returns the QC from the block.
	// - If the block is a normal block, this returns the QC from validators' votes for the previous block
	// - If the block contains a timeout QC, this returns the validator high QC aggregated from
	//   validators' timeout messages
	// We are able to simplify the GetQC() to this behavior because this QC is only needed to construct
	// a timeout QC for the next block in the event of a timeout. So, this QC will always be the latest QC
	// at the current chain's tip that subsequent blocks will build on top of.
	GetQC() QuorumCertificate
}

type BlockWithValidators struct {
	Block Block
	// The validator set for the next block height after the block. This validator set can be used to validate
	// votes and timeouts used to build a QC that extends from the block. The validator set must be sorted
	// in descending order of stake amount with a consistent tie breaking scheme.
	Validators []Validator
}

// We want a large buffer for the signal channels to ensure threads don't block when trying to push new
// signals.
//
// TODO: is a size of 100 enough? If we want to bullet-proof this, we could back it by a slice as a
// secondary buffer. That seems unnecessary since every channel will only have signals pushed by a single
// producer thread.
const signalChannelBufferSize = 100

// An instance of FastHotStuffEventLoop is a self-contained module that represents a single node running
// the event loop for the Fast HotStuff consensus protocol. The event loop is initialized at the current chain's
// tip, with a given block hash, block height, view number, and validator set. The event loop is simplified and
// does not know whether its role is that of a block proposer or a replica validator.
//
// Given a block that's at the tip of the current chain, the event loop maintains its own internal data structures
// and runs an internal event loop that handles all of the following:
//   - Tracking of the current view, incrementing the view during timeouts, and computing exponential
//     back-off durations during consecutive timeouts
//   - Aggregation of votes and QC construction for the current block
//   - Aggregation of timeout messages for the current view
//   - Signaling the server when it can vote on the current tip block
//   - Signaling the server when it has timed out the current view
//   - Signaling the server when it has a QC for the current tip block
//   - Signaling the server when it has a timeout QC for the current view
//
// When a new block is connected to the chain, the server is expected to update the tip block. The event loop
// resets all internal data structures and scheduled tasks to handle all of the above based on the new tip.
//
// This event loop is simple and only houses the logic that decides what action to perform next given the
// current tip block. The event loop does not track the full history of blocks, and instead needs the server
// to pass in the tip block and safe extendable blocks. It expects the server to maintain the block chain,
// the index of all past blocks, to perform QC validations for incoming blocks, to handle the commit rule, to
// handle reorgs, and to only then to pass the the new validated tip.
type FastHotStuffEventLoop struct {
	lock sync.RWMutex

	crankTimerInterval  time.Duration
	timeoutBaseDuration time.Duration

	crankTimerTask  *ScheduledTask[uint64]
	nextTimeoutTask *ScheduledTask[uint64]

	// The current view at which we expect to see or propose the next block. In the event of a timeout,
	// the timeout signal will be triggered for this view.
	currentView uint64

	// Signifies whether or not the event loop has constructed a QC or timeout QC for the current view.
	// This is an optimization that is useful to prevent the event loop from signaling the server multiple
	// times for the same view.
	hasConstructedQCInCurrentView bool

	// Block hash of the current tip of the block-chain.
	tip blockWithValidatorLookup

	// All blocks that are safe to extend from. This will include the committed tip and all uncommitted
	// descendants that are safe to extend from. This slice also includes the tip block itself.
	safeBlocks []blockWithValidatorLookup

	// votesSeen is an in-memory map of all the votes we've seen so far. It's a nested map with the
	// following nested key structure:
	//
	//   sha3-256(vote.View, vote.BlockHash) - > string(vote.PublicKey) -> VoteMessage
	//
	// We use a nested map as above because we want to be able to efficiently fetch all votes by block hash.
	votesSeen map[[32]byte]map[string]VoteMessage

	// timeoutsSeen is an in-memory map of all the timeout messages we've seen so far, organized by
	// the timed out view and the BLS public key string of the sender. We use a nested map because
	// we want to be able to fetch all timeout messages by view.
	timeoutsSeen map[uint64]map[string]TimeoutMessage

	// Externally accessible channel for signals sent to the Server.
	Events chan *FastHotStuffEvent

	// Internal statuses and wait groups used to coordinate the start and stop operations for
	// the event loop.
	status eventLoopStatus
}

type eventLoopStatus byte

const (
	eventLoopStatusNotInitialized eventLoopStatus = 0 // Not initialized and the event loop is not running
	eventLoopStatusInitialized    eventLoopStatus = 1 // Initialized but the event loop is not running
	eventLoopStatusRunning        eventLoopStatus = 2 // Initialized and the event loop is running
)
