package consensus

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/holiman/uint256"
)

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

func (node *validatorNode) ProcessBlock(block Block) {

	safeBlocks := append(node.safeBlocks, block)

	node.eventLoop.ProcessTipBlock(
		BlockWithValidators{block, node.castValidators()},
		collections.Transform(safeBlocks, func(block Block) BlockWithValidators {
			return BlockWithValidators{block, node.castValidators()}
		}),
	)
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
