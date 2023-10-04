package consensus

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/holiman/uint256"
)

//////////////////////////////////////////////////////////
// Validator Node implementation for testing
//////////////////////////////////////////////////////////

type validatorNode struct {
	privateKey *bls.PrivateKey
	stake      *uint256.Int

	eventLoop *FastHotStuffEventLoop

	isBlockProposer bool
	validators      []*validatorNode

	safeBlocks []Block
	quit       chan struct{}
}

func (node *validatorNode) castValidators() []Validator {
	return collections.Transform(node.validators, func(validator *validatorNode) Validator {
		return validator
	})
}

func (node *validatorNode) GetPublicKey() *bls.PublicKey {
	return node.privateKey.PublicKey()
}

func (node *validatorNode) GetStakeAmount() *uint256.Int {
	return node.stake
}

func (node *validatorNode) ProcessBlock(block *block) {
	// Make sure that the block contains a valid QC, signature, transactions,
	// and that it's for the current view.
	if !node.sanityCheckBlock(block) {
		return
	}

	// The safeVote variable will tell us if we can vote on this block.
	safeVote := false

	// If the block doesn’t contain an AggregateQC, then that indicates that we
	// did NOT timeout in the previous view, which means we should just check that
	// the QC corresponds to the previous view.
	if isInterfaceNil(block.aggregateQC) {
		// The block is safe to vote on if it is a direct child of the previous
		// block. This means that the parent and child blocks have consecutive
		// views. We use the current block’s QC to find the view of the parent.
		safeVote = block.GetView() == block.GetQC().GetView()+1
	} else {
		// If we have an AggregateQC set on the block, it means the nodes decided
		// to skip a view by sending TimeoutMessages to the leader, so we process
		// the block accordingly.

		// First we make sure the block contains a valid AggregateQC.
		node.validateTimeoutProof(block.AggregateQC)

		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.
		highestTimeoutQC := block.AggregateQC.ValidatorTimeoutHighQC

		// If our local highestQC has a smaller view than the highestTimeoutQC,
		// we update our local highestQC.
		if highestTimeoutQC.View > node.HighestQC.View {
			node.HighestQC = &(highestTimeoutQC)
		}

		// We make sure that the block’s QC matches the view of the highest QC that we’re aware of.
		safeVote = block.QC.View == node.HighestQC.View && block.AggregateQC.View+1 == block.View
	}

	safeBlocks := append(node.safeBlocks, block)

	node.eventLoop.ProcessTipBlock(
		BlockWithValidators{block, node.castValidators()},
		collections.Transform(safeBlocks, func(block Block) BlockWithValidators {
			return BlockWithValidators{block, node.castValidators()}
		}),
	)
}

// sanityCheckBlock is used to verify that the block contains valid information.
func (node *validatorNode) sanityCheckBlock(block Block) bool {
	// We ensure the currently observed block is either for the current view, or for a future view.
	if block.GetView() < node.eventLoop.currentView {
		return false
	}

	// The block's QC should never be empty.
	if !isProperlyFormedBlock(block) {
		return false
	}

	// We make sure the QC contains valid signatures from 2/3rds of validators, weighted by stake. And that the
	// combined signature is valid.
	if !IsValidSuperMajorityQuorumCertificate(block.GetQC(), node.castValidators()) {
		return false
	}

	return true
}

func (node *validatorNode) ProcessVote(vote VoteMessage) {
	node.eventLoop.ProcessValidatorVote(vote)
}

func (node *validatorNode) ProcessTimeout(timeout TimeoutMessage) {
	node.eventLoop.ProcessValidatorTimeout(timeout)
}

func (node *validatorNode) Start() {
	node.eventLoop.Start()

	for {
		select {
		case event := <-node.eventLoop.Events:
			switch event.EventType {
			case FastHotStuffEventTypeVote:
				node.BroadcastVote(event)
				break
			case FastHotStuffEventTypeTimeout:
				node.BroadcastTimeout(event)
				break
			case FastHotStuffEventTypeConstructVoteQC:
				node.BroadcastBlockWithVoteQC(event)
				break
			case FastHotStuffEventTypeConstructTimeoutQC:
				node.BroadcastBlockWithTimeoutQC(event)
				break
			}
		case <-node.quit:
			return
		}
	}
}

func (node *validatorNode) BroadcastVote(event *FastHotStuffEvent) {
	payload := GetVoteSignaturePayload(event.View, event.TipBlockHash)
	signature, err := node.privateKey.Sign(payload[:])
	if err != nil {
		panic(err)
	}

	vote := &voteMessage{
		view:      event.View,
		blockHash: event.TipBlockHash,
		publicKey: node.privateKey.PublicKey(),
		signature: signature,
	}

	for _, validator := range node.validators {
		validator.ProcessVote(vote)
	}
}

func (node *validatorNode) BroadcastTimeout(event *FastHotStuffEvent) {
	payload := GetTimeoutSignaturePayload(event.View, event.AggregateQC.GetHighQC().GetView())
	signature, err := node.privateKey.Sign(payload[:])
	if err != nil {
		panic(err)
	}

	timeout := &timeoutMessage{
		view:      event.View,
		highQC:    event.AggregateQC.GetHighQC(),
		publicKey: node.privateKey.PublicKey(),
		signature: signature,
	}

	for _, validator := range node.validators {
		validator.ProcessTimeout(timeout)
	}
}

func (node *validatorNode) BroadcastBlockWithVoteQC(event *FastHotStuffEvent) {
	block := &block{
		view:      event.View + 1,
		blockHash: createDummyBlockHash(),
		height:    event.TipBlockHeight + 1,
		qc:        event.QC,
	}

	for _, validator := range node.validators {
		validator.ProcessBlock(block)
	}
}

func (node *validatorNode) BroadcastBlockWithTimeoutQC(event *FastHotStuffEvent) {
	block := &block{
		view:      event.View + 1,
		blockHash: createDummyBlockHash(),
		height:    event.TipBlockHeight + 1,
		qc:        event.QC,
	}

	for _, validator := range node.validators {
		validator.ProcessBlock(block)
	}
}

func (node *validatorNode) Stop() {
	node.eventLoop.Stop()
	node.quit <- struct{}{}
}
