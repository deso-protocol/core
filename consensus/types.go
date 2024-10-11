package consensus

import (
	"sync"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections/bitset"
	"github.com/deso-protocol/uint256"
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

// SignatureOpCode is a way for the FastHotStuffEventLoop to differentiate between different types of
// BLS signatures. This is used to ensure that the event loop doesn't accidentally sign two different
// message types with the same signature.
//   - SignatureOpCodeValidatorVote: The BLS signature is for a validator vote message
//   - SignatureOpCodeValidatorTimeout: The BLS signature is for a validator timeout message
type SignatureOpCode byte

const (
	SignatureOpCodeValidatorVote    SignatureOpCode = 1
	SignatureOpCodeValidatorTimeout SignatureOpCode = 2
)

func (opCode SignatureOpCode) ToBytes() []byte {
	return []byte{byte(opCode)}
}

// The maximum number of consecutive timeouts that can occur before the event loop stops
// its exponential back-off. This is a safety valve that helps ensure that the event loop
// doesn't get stuck in a near indefinite back-off state.
const maxConsecutiveTimeouts = 16

// Create an alias type of the 32 bit block hash so that the raw [32]byte type isn't
// ambiguously repeated in the code base
type BlockHashValue = [32]byte

// FastHotStuffEventLoop is the public facing interface for the consensus event loop. We expose an
// interface instead of the raw event loop struct to allow external callers to mock the event loop
// for testing purposes.
type FastHotStuffEventLoop interface {
	GetEvents() chan *FastHotStuffEvent

	Init(time.Duration, time.Duration, QuorumCertificate, BlockWithValidatorList, []BlockWithValidatorList, uint64) error
	GetCurrentView() uint64
	AdvanceViewOnTimeout() (uint64, error)
	ProcessTipBlock(BlockWithValidatorList, []BlockWithValidatorList, time.Duration, time.Duration) error
	UpdateSafeBlocks([]BlockWithValidatorList) error
	ProcessValidatorVote(VoteMessage) error
	ProcessValidatorTimeout(TimeoutMessage) error
	Start()
	Stop()
	IsInitialized() bool
	IsRunning() bool
	ToString() string
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
	GetDomains() [][]byte
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
	// The QC field is intentionally excluded from the Block interface to minimize the number of assumptions
	// and validation the event loop has to make on incoming blocks. This is especially important for the
	// PoW -> PoS cutover blocks that do not have QCs.
}

type BlockWithValidatorList struct {
	Block Block
	// The ordered validator list for the next block height after the block. This validator list can be used to
	// validate votes and timeouts used to build a QC that extends from the block. The validator list must be
	// sorted in descending order of stake amount with a consistent tie breaking scheme.
	ValidatorList []Validator
}

// Any large number is sufficient to hold the backlog of signals to be sent to the server. In practice there will
// be 0 0 - 2 signals at most in this buffer at any given time.
const signalChannelBufferSize = 10000

// An instance of FastHotStuffEventLoop is a self-contained module that represents a single node running
// the event loop for the Fast HotStuff consensus protocol. The event loop is initialized at the current chain's
// tip, with a given block hash, block height, view number, and validator list. The event loop is simplified and
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
type fastHotStuffEventLoop struct {
	lock sync.RWMutex

	crankTimerInterval  time.Duration
	timeoutBaseDuration time.Duration

	crankTimerTask  *ScheduledTask[uint64]
	nextTimeoutTask *ScheduledTask[uint64]

	// The current view at which we expect to see or propose the next block. In the event of a timeout,
	// the timeout signal will be triggered for this view.
	currentView uint64

	// These track whether the event loop has already run the crank timer for the current view and
	// constructed a QC for the current view. They ensure that we only attempt to construct a QC once
	// the crank timer has elapsed, and only signal for QC construction once per view.
	hasCrankTimerRunForCurrentView bool
	hasConstructedQCInCurrentView  bool

	// Quorum certificate used as the genesis for the PoS chain. This QC is a trusted input that is used
	// to override the highQC in timeout messages and timeout aggregate QCs when there is a timeout at the
	// first block height of the PoS chain.
	genesisQC QuorumCertificate

	// Block hash of the current tip of the block-chain.
	tip blockWithValidatorLookup

	// All blocks that are safe to extend from. This will include the committed tip and all uncommitted
	// descendants that are safe to extend from. This slice also includes the tip block itself.
	safeBlocks []blockWithValidatorLookup

	// votesSeenByBlockHash is an in-memory map of all the votes we've seen so far. It's a nested map with
	// the following nested key structure:
	//
	//   sha3-256(vote.View, vote.BlockHash) - > string(vote.PublicKey) -> VoteMessage
	//
	// We use a nested map as above because we want to be able to efficiently fetch all votes by block hash.
	votesSeenByBlockHash map[BlockHashValue]map[string]VoteMessage

	// timeoutsSeenByView is an in-memory map of all the timeout messages we've seen so far, organized by
	// the timed out view and the BLS public key string of the sender. We use a nested map because
	// we want to be able to fetch all timeout messages by view.
	timeoutsSeenByView map[uint64]map[string]TimeoutMessage

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
