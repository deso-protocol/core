package lib

// The BlockProposer is responsible for:
// - it knows when the current node is the block proposer for the network
// - it tracks its own time crank timer
type BlockProposer struct {
}

func (bp *BlockProposer) ProcessVoteMsg(msg *MsgDeSoValidatorVote) {
}

func (bp *BlockProposer) ProcessTimeout(msg *MsgDeSoValidatorTimeout) {
}

func (bp *BlockProposer) ProcessBlock(msg *MsgDeSoBlock) {
}

func (bp *BlockProposer) ConstructBlockTemplate(blockView *UtxoView, mempool *DeSoMempool /*Update to *DeSoMempoolPoS*/) *MsgDeSoBlock {
	return nil
}
