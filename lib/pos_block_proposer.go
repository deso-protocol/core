package lib

import "github.com/deso-protocol/core/bls"

type BlockProposalReadySignal struct {
	BlockHeight uint64
}

// BlockProposer is a stateful construct that encapsulates all block proposal and signing logic.
// Block proposal can be triggered by an external event (vote msg, timeout msg, block msg) or by
// an internal timer that regulates block production cadence. The BlockProposer does not know
// or regulate consensus view durations, but greedily signals when it can propose a block
// for simplicity. The server can ignore the signal when appropriate.
//
// The BlockProposer does all of the following:
// - Maintains an internal timer to regulate the block production cadence
// - Processes vote messages for signature aggregation and QC construction
// - Processes timeout messages for signature aggregation and timeout QC construction
// - Processes incoming blocks for vote & timeout validation, and next block construction
// - Constructs a signed block that is ready for broadcast
// - Emit a signal to the server when it is ready to construct and broadcast a block
type BlockProposer struct {
	// Used to signal the server when a block can be proposed
	ReadyBlockHeights <-chan BlockProposalReadySignal
}

func NewBlockProposer() *BlockProposer {
	return &BlockProposer{
		ReadyBlockHeights: make(chan BlockProposalReadySignal),
	}
}

// Runs the block proposer's internal timer that regulates block production cadence, and
// signals when a block can be proposed.
func (bp *BlockProposer) Start() {
	// TODO
}

func (bp *BlockProposer) Stop() {
	// TODO
}

// SetCommittee sets the validator set public keys. The validator set
// public keys are needed here to validate incoming votes and timeouts.
func (bp *BlockProposer) SetCommittee(
	leaderSchedulePublicKeys []bls.PublicKey,
	validatorSetPublicKeys []bls.PublicKey,
) error {
	// TODO
	return nil
}

func (bp *BlockProposer) SetSigner(signer bls.PrivateKey) error {
	// TODO
	return nil
}

// ProcessVote processes an incoming vote message. This function does the following:
// - Validates the incoming vote against a previously seen block, or caches the timeout if the block is not seen yet
// - Caches the vote signature for signature aggregation
// - Determines if the vote is enough to construct a QC and signals the server
// for the purposes of block proposal.
func (bp *BlockProposer) ProcessVote(vote *MsgDeSoValidatorVote) error {
	// TODO
	return nil
}

// ProcessVote processes an incoming timeout message. This function does the following:
// - Validates the timeout against a previously seen block, or caches the timeout if the block is not seen yet
// - Caches the timeout signature for signature aggregation
// - Determines if the timeout message is enough to construct a QC and signals the server
// for the purposes of block proposal.
func (bp *BlockProposer) ProcessTimeout(timeout *MsgDeSoValidatorTimeout) error {
	// TODO
	return nil
}

// BlockAccepted is called when a block has been processed and added to the blockchain's tip. This function
// does the following:
// - Extracts the proposer's signature from the block for later signature aggregation
// - Caches the block hash for signature validation from previous received and future vote/timeout messages
// - Determines if the proposer's signature in the block is enough to construct a QC for the next block, and signals the server
func (bp *BlockProposer) BlockAccepted(blockHeader *MsgDeSoHeader) error {
	// TODO
	return nil
}

// ConstructBlock constructs a block based on the the signatures it has seen for a block at the preceding height.
// This function must be idempotent and should have no side-effects.
func (bp *BlockProposer) ConstructBlock(
	blockView *UtxoView, // The blockView at the height blockHeight-1
	blockHeight uint64, // The next block's height, which the block proposer has signaled that it is ready to construct
	viewNumber uint64, // The next block's consensus view number
	// TODO: Add PosMempool as a parameter here
) (*MsgDeSoBlock, error) {
	// TODO
	return nil, nil
}
