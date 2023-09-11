package consensus

import (
	"sync"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/holiman/uint256"
)

// ConsensusEvent is a way for FastHotStuffEventLoop to send messages back to the Server.
// There are four types of events that can be sent:
//   - ConsensusEventTypeVote: The consensus is ready to vote on a block at a given block height and view
//   - ConsensusEventTypeTimeout: The consensus has timed out on a view
//   - ConsensusEventTypeConstructVoteQC: The consensus has a QC for a block and is ready to construct the
//     next block at the next block height and the current view
//   - ConsensusEventTypeConstructTimeoutQC: The consensus has a timeout QC for a view and is ready to
//     construct an empty block with the timeout QC at the next block height and the current view

type ConsensusEventType byte

const (
	ConsensusEventTypeVote               ConsensusEventType = 0
	ConsensusEventTypeTimeout            ConsensusEventType = 1
	ConsensusEventTypeConstructVoteQC    ConsensusEventType = 2
	ConsensusEventTypeConstructTimeoutQC ConsensusEventType = 3
)

type ConsensusEvent struct {
	EventType   ConsensusEventType
	BlockHash   BlockHash
	BlockHeight uint64
	View        uint64
}

// BlockHash is a 32-byte hash of a block used to uniquely identify a block. It's re-defined here
// as an interface that matches the exact structure of the BlockHash type in core, so that the two
// packages are decoupled and the Fast HotStuff consensus can be tested end-to-end independently.
// When using the Fast HotStuff, the lib package can convert its own BlockHash type to and from this
// type trivially.
type BlockHash interface {
	GetValue() [32]byte
}

type Validator interface {
	GetPublicKey() *bls.PublicKey
	GetStakeAmount() *uint256.Int
}

type QuorumCertificate interface {
	GetBlockHash() BlockHash
	GetView() uint64
	GetSignersList() *bitset.Bitset
	GetAggregatedSignature() *bls.Signature
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

// We want a large buffer for the signal channels to ensure threads don't block when trying to push new
// signals.
//
// TODO: is a size of 100 enough? If we want to bullet-proof this, we could back it by a slice as a
// secondary buffer. That seems unnecessary since every channel will only have signals pushed by a single
// producer thread.
const signalChannelBufferSize = 100

// An instance of FastHotStuffEventLoop is a self-contained module that represents a single node running
// the event loop for the Fast HotStuff consensus protocol. The module is initialized at the current chain's
// tip, with a given block hash, block height, view number, and validator set. The module is simplified and
// does not know whether its role is that of a block proposer or a replica validator.
//
// Given a block that's at the tip of the current chain, this module maintains its own internal data structures
// and runs internal timers that handles all of the following:
//   - Tracking of the current view, incrementing the view during timeouts, and computing exponential
//     back-off durations during consecutive timeouts
//   - Aggregation of votes and QC construction for the current block
//   - Aggregation of timeout messages for the current view
//   - Signaling its caller when it can vote on the current chain tip
//   - Signaling its caller when it has timed out the current view
//   - Signaling its caller when it has a QC for the current block
//   - Signaling its caller when it has a timeout QC for the current view
//
// When a new block is connected to the chain, the caller is expected to update the chain tip. The module
// resets all internal data structures and timers to handle all of the above based on the new chain tip.
//
// This module is very simple and only houses the logic that decides what action to perform next given the
// current chain tip. The module does not track the history of blocks, and instead needs its caller to
// update the block at the current chain tip. It expects its caller to maintain the block chain,
// the index of all past blocks, to perform QC validations for incoming blocks, to handle the commit rule,
// and only then to pass the validated chain tip. Note: this module takes the provided chain tip as a
// trusted input and does NOT validate any incoming blocks. This also mean the module expects its caller to
// track historical vote and timeout messages it has sent so as to not vote more than once at a given view
// or block height.
type FastHotStuffEventLoop struct {
	lock sync.RWMutex

	blockConstructionCadence time.Duration
	timeoutBaseDuration      time.Duration

	nextBlockConstructionTimeStamp time.Time
	nextTimeoutTimeStamp           time.Time

	// The latest block accepted by the caller. We only keep track of the latest safe block here because
	// it's the block we vote on, and construct a vote QC for.
	chainTip Block
	// The current view at which we expect to see or propose the next block. In the event of a timeout,
	// the timeout signal will be triggered for this view.
	currentView uint64
	// The validator set sorted in decreasing order of stake amount, with a consistent tie-breaking
	// scheme. This validator set is expected to be valid for validating votes and timeouts for the
	// next block height.
	validatorsAtChainTip []Validator

	// votesSeen is an in-memory map of all the votes we've seen so far. It's a nested map with the
	// following nested key structure:
	//
	//   sha256(vote.View, vote.BlockHash) - > string(vote.PublicKey) -> VoteMessage
	//
	// We use a nested map as above because we want to be able to efficiently fetch all votes by block hash.
	votesSeen map[[32]byte]map[string]VoteMessage

	// timeoutsSeen is an in-memory map of all the timeout messages we've seen so far, organized by
	// the timed out view and the BLS public key string of the sender. We use a nested map because
	// we want to be able to fetch all timeout messages by view.
	timeoutsSeen map[uint64]map[string]TimeoutMessage

	// Externally accessible channel for signals sent to the Server.
	ConsensusEvents chan *ConsensusEvent

	// Internal channels used by this module to coordinate the event loop
	resetEventLoopSignal chan interface{}
	stopSignal           chan interface{}

	// Internal statuses and wait groups used to coordinate the start and stop operations for
	// the event loop.
	status     consensusStatus
	startGroup sync.WaitGroup
	stopGroup  sync.WaitGroup
}

type consensusStatus byte

const (
	consensusStatusNotInitialized consensusStatus = 0 // Not initialized and the event loop is not running
	consensusStatusInitialized    consensusStatus = 1 // Initialized but the event loop is not running
	consensusStatusRunning        consensusStatus = 2 // Initialized and the event loop is running
)
