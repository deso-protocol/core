package consensus

import (
	"github.com/golang/glog"
	"sync"
	"time"

	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
	"github.com/deso-protocol/uint256"
)

// validatorNode is a simplified implementation of a Fast-HotStuff node that runs the Fast-HotStuff
// event loop. It is adapted into a working state from the reference implementation at:
// https://github.com/deso-protocol/hotstuff_pseudocode/blob/main/fast_hotstuff_bls.go
//
// This node implementation implementation has no networking, and no node syncing. It's a bare-bones
// implementation that runs the the Fast-HotStuff protocol for a single node. It is used to test the
// correctness of the Fast-HotStuff event loop in integration testing.
type validatorNode struct {
	lock *sync.Mutex

	privateKey *bls.PrivateKey
	stake      *uint256.Int

	eventLoop *fastHotStuffEventLoop

	isBlockProposer bool
	validatorNodes  []*validatorNode

	latestCommittedBlock Block

	safeBlocks map[[32]byte]*block
	quit       chan struct{}
}

func newValidatorNode(stake *uint256.Int, isBlockProposer bool) *validatorNode {
	return &validatorNode{
		lock:            &sync.Mutex{},
		privateKey:      createDummyBLSPrivateKey(),
		stake:           stake,
		eventLoop:       NewFastHotStuffEventLoop(),
		isBlockProposer: isBlockProposer,

		quit: make(chan struct{}),
	}
}

func (node *validatorNode) Init(
	crankTimerInterval time.Duration,
	timeoutBaseDuration time.Duration,
	genesisBlock *block,
	validatorNodes []*validatorNode,
) error {
	node.lock.Lock()
	defer node.lock.Unlock()

	node.validatorNodes = validatorNodes
	node.safeBlocks = map[[32]byte]*block{
		genesisBlock.GetBlockHash().GetValue(): genesisBlock,
	}

	return node.eventLoop.Init(
		crankTimerInterval,
		timeoutBaseDuration,
		genesisBlock.qc,
		BlockWithValidatorList{genesisBlock, node.getValidators()},
		[]BlockWithValidatorList{
			{genesisBlock, node.getValidators()},
		},
		genesisBlock.GetView()+1,
	)
}

func (node *validatorNode) Resync(genesisBlock *block, tipBlock *block, safeBlocks []*block) error {
	node.lock.Lock()
	defer node.lock.Unlock()

	safeBlocks = append(safeBlocks, tipBlock)
	node.safeBlocks = collections.ToMap(safeBlocks, func(bb *block) [32]byte {
		return bb.GetBlockHash().GetValue()
	})

	return node.eventLoop.Init(
		node.eventLoop.crankTimerInterval,
		node.eventLoop.timeoutBaseDuration,
		genesisBlock.qc,
		BlockWithValidatorList{tipBlock, node.getValidators()},
		collections.Transform(safeBlocks, func(bb *block) BlockWithValidatorList {
			return BlockWithValidatorList{bb, node.getValidators()}
		}),
		genesisBlock.GetView()+1,
	)
}

func (node *validatorNode) getValidators() []Validator {
	return collections.Transform(node.validatorNodes, func(validator *validatorNode) Validator {
		return validator
	})
}

func (node *validatorNode) GetPublicKey() *bls.PublicKey {
	return node.privateKey.PublicKey()
}

func (node *validatorNode) GetStakeAmount() *uint256.Int {
	return node.stake
}

func (node *validatorNode) GetDomains() [][]byte {
	return [][]byte{}
}

func DomainsToString(domainsBytes [][]byte) string {
	domains := ""
	for _, domain := range domainsBytes {
		domains += string(domain) + ", "
	}
	return domains
}

func (node *validatorNode) GetDomainsString() string {
	return DomainsToString(node.GetDomains())
}

func (node *validatorNode) ProcessBlock(incomingBlock *block) {
	node.lock.Lock()
	defer node.lock.Unlock()

	if node.eventLoop.status != eventLoopStatusRunning {
		return
	}

	// Make sure that the block contains a valid QC, signature, transactions,
	// and that it's for the current view.
	if !node.sanityCheckBlock(incomingBlock) {
		return
	}

	// The safeVote variable will tell us if we can accept this block and vote on it.
	safeVote := false

	// If the block doesn’t contain an AggregateQC, then that indicates that we
	// did NOT timeout in the previous view, which means we should just check that
	// the QC corresponds to the previous view.
	if isInterfaceNil(incomingBlock.aggregateQC) {
		// The block is safe to vote on if it is a direct child of the previous
		// block. This means that the parent and child blocks have consecutive
		// views. We use the current block’s QC to find the view of the parent.
		safeVote = incomingBlock.GetView() == incomingBlock.GetQC().GetView()+1
	} else {
		// If we have an AggregateQC set on the block, it means the nodes decided
		// to skip a view by sending TimeoutMessages to the leader, so we process
		// the block accordingly.

		// We find the QC with the highest view among the QCs contained in the
		// AggregateQC.
		highestTimeoutQC := incomingBlock.aggregateQC.GetHighQC()

		// We make sure that the block’s QC matches the view of the highest QC that we’re aware of.
		safeVote = incomingBlock.aggregateQC.GetHighQC().GetView() == highestTimeoutQC.GetView() &&
			incomingBlock.aggregateQC.GetView()+1 == node.eventLoop.currentView
	}

	// If the block isn't safe to process locally, then there's nothing else to do.
	if !safeVote {
		return
	}

	// Store the block locally.
	node.safeBlocks[incomingBlock.blockHash.GetValue()] = incomingBlock

	// Run the commit rule.
	node.commitChainFromGrandParent(incomingBlock)

	// Update the event loop with the new block as the chain tip.
	node.eventLoop.ProcessTipBlock(
		BlockWithValidatorList{incomingBlock, node.getValidators()},
		collections.Transform(
			collections.MapValues(node.safeBlocks),
			func(bb *block) BlockWithValidatorList {
				return BlockWithValidatorList{bb, node.getValidators()}
			},
		),
		// TODO: replace with values from snapshot global params
		node.eventLoop.crankTimerInterval,
		node.eventLoop.timeoutBaseDuration,
	)
}

// sanityCheckBlock is used to verify that the block contains valid information.
func (node *validatorNode) sanityCheckBlock(block *block) bool {
	// We ensure the currently observed block is either for the current view, or for a future view.
	if block.GetView() < node.eventLoop.currentView {
		return false
	}

	// The block's should be properly formatted.
	if !isProperlyFormedBlock(block) {
		return false
	}

	// We make sure the QC contains valid signatures from 2/3rds of validators, weighted by stake. And that the
	// combined signature is valid.
	if !IsValidSuperMajorityQuorumCertificate(block.GetQC(), node.getValidators()) {
		return false
	}

	// If the block doesn't contain a timeout QC, then we're done.
	if !isInterfaceNil(block.qc) && isInterfaceNil(block.aggregateQC) {
		return true
	}

	// If the block contains a timeout QC, then we make sure the it is a valid aggregate QC.
	if !node.validateTimeoutProof(block.aggregateQC) {
		return false
	}

	return true
}

// validateTimeoutProof is used to verify that the validators included in the QC collectively own at least 2/3rds
// of the stake. Also make sure there are no repeated public keys. Note the bitset in the signature allows us to
// determine how much stake the validators had.
func (node *validatorNode) validateTimeoutProof(aggregateQC AggregateQuorumCertificate) bool {
	// Extract the highest QC view from the AggregateQC.
	highestQCView := uint64(0)
	for _, view := range aggregateQC.GetHighQCViews() {
		if view > highestQCView {
			highestQCView = view
		}
	}

	// The highest QC view found in the signatures should match the highest view
	// of the HighestQC included in the AggregateQC.
	if highestQCView != aggregateQC.GetHighQC().GetView() {
		return false
	}

	// Verify the HighQC included in the AggregateQC.
	if !IsValidSuperMajorityQuorumCertificate(aggregateQC.GetHighQC(), node.getValidators()) {
		return false
	}

	// Extract the payload that every validator would have signed for the aggregate QC.
	signedPayloads := [][]byte{}
	for _, highQCView := range aggregateQC.GetHighQCViews() {
		payload := GetTimeoutSignaturePayload(aggregateQC.GetView(), highQCView)
		signedPayloads = append(signedPayloads, payload[:])
	}

	// Extract the public keys of the validators that signed the aggregate QC.
	signersList := aggregateQC.GetAggregatedSignature().GetSignersList()
	signerPublicKeys := []*bls.PublicKey{}

	for ii := 0; ii < signersList.Size(); ii++ {
		signerPublicKeys = append(signerPublicKeys, node.validatorNodes[ii].GetPublicKey())
	}

	// Validate the signers' aggregate signatures.
	isValidSignature, err := bls.VerifyAggregateSignatureMultiplePayloads(
		signerPublicKeys,
		aggregateQC.GetAggregatedSignature().GetSignature(),
		signedPayloads,
	)
	if err != nil || !isValidSignature {
		return false
	}

	return true
}

// commitChainFromGrandParent represents our commit rule. It is called whenever we receive a new block to determine
// if we can commit any blocks that we've previously received. The Fast-HotStuff commit rule finalizes blocks once
// we observe a two-chain involving a direct one-chain. In other words, we must observe a sequence of three blocks:
//
//	B1 - B2 - B3
//
// such that B1 is the parent of B2, and B2 is an ancestor of B3. The ancestor-descendant relationship is established
// whenever a block contains the QC for another block. We say that this block is the descendant of the other block.
// In particular, if the two blocks were proposed with consecutive views, we say these blocks are in a parent-child
// relationship. So, when we observe the aforementioned configuration of B1, B2, and B3, we finalize all ancestors of
// B1 as well as B1. To see why this is safe, one is referred to read the Fast-HotStuff paper.
func (node *validatorNode) commitChainFromGrandParent(block *block) {
	// In accordance to the above comment, B3 = block, B2 = parent, and B1 = grandParent.
	parent := node.safeBlocks[block.GetQC().GetBlockHash().GetValue()]
	if parent == nil {
		return
	}

	// We verify that B2 is the parent of B3.
	if block.GetView() != (parent.GetView() + 1) {
		return
	}

	grandParent := node.safeBlocks[parent.GetQC().GetBlockHash().GetValue()]
	if grandParent == nil {
		return
	}

	// We verify that B1 is the parent of B2.
	if parent.GetView() != (grandParent.GetView() + 1) {
		return
	}

	// We have successfully observed a committing configuration, we will now commit all ancestors of B1 as well as B1.
	node.latestCommittedBlock = grandParent
}

func (node *validatorNode) ProcessVote(vote VoteMessage) {
	node.lock.Lock()
	defer node.lock.Unlock()

	if node.eventLoop.status != eventLoopStatusRunning {
		return
	}

	node.eventLoop.ProcessValidatorVote(vote)
}

func (node *validatorNode) ProcessTimeout(timeout TimeoutMessage) {
	node.lock.Lock()
	defer node.lock.Unlock()

	if node.eventLoop.status != eventLoopStatusRunning {
		return
	}

	if err := node.eventLoop.ProcessValidatorTimeout(timeout); err != nil {
		glog.V(2).Infof("ProcessTimeout: Error processing timeout from validator %v: %v",
			timeout.GetPublicKey().ToString(), err)
	}
}

func (node *validatorNode) Start() {
	node.eventLoop.Start()
	go node.runEventSignalLoop()
}

func (node *validatorNode) runEventSignalLoop() {
	for {
		select {
		case event := <-node.eventLoop.Events:
			switch event.EventType {
			case FastHotStuffEventTypeVote:
				node.handleVoteEvent(event)
				break
			case FastHotStuffEventTypeTimeout:
				node.handleTimeoutEvent(event)
				break
			case FastHotStuffEventTypeConstructVoteQC:
				node.handleVoteQCConstructionEvent(event)
				break
			case FastHotStuffEventTypeConstructTimeoutQC:
				node.handleTimeoutQCConstructionEvent(event)
				break
			}
		case <-node.quit:
			return
		}
	}
}

func (node *validatorNode) handleVoteEvent(event *FastHotStuffEvent) {
	node.lock.Lock()
	defer node.lock.Unlock()

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

	for _, validator := range node.validatorNodes {
		go validator.ProcessVote(vote)
	}
}

func (node *validatorNode) handleTimeoutEvent(event *FastHotStuffEvent) {
	node.lock.Lock()
	defer node.lock.Unlock()

	// Skip if the timed out view from the event is stale
	if node.eventLoop.currentView != event.View {
		return
	}

	// Skip if the node can't advance to the next view for some reason.
	// This should never happen.
	if _, err := node.eventLoop.AdvanceViewOnTimeout(); err == nil {
		node.broadcastTimeout(event)
	}
}

func (node *validatorNode) broadcastTimeout(event *FastHotStuffEvent) {
	highQC := node.safeBlocks[event.TipBlockHash.GetValue()].GetQC()
	payload := GetTimeoutSignaturePayload(event.View, highQC.GetView())
	signature, err := node.privateKey.Sign(payload[:])
	if err != nil {
		panic(err)
	}

	timeout := &timeoutMessage{
		view:      event.View,
		highQC:    highQC,
		publicKey: node.privateKey.PublicKey(),
		signature: signature,
	}

	// Broadcast the block to all validators.
	for _, validator := range node.validatorNodes {
		glog.V(2).Infof("broadcastTimeout: Broadcasting timeout message from validator "+
			"%v (%v) to validator %v (%v)", node.GetDomainsString(), node.GetPublicKey().ToString(),
			validator.GetDomainsString(), validator.GetPublicKey().ToString())
		go validator.ProcessTimeout(timeout)
	}
}

func (node *validatorNode) handleVoteQCConstructionEvent(event *FastHotStuffEvent) {
	node.lock.Lock()
	defer node.lock.Unlock()

	if !node.isBlockProposer {
		return
	}

	// Skip if the view from the event is stale. This can happen if the node
	// has advances to the next view before the block is processed.
	if node.eventLoop.currentView != event.View {
		return
	}

	block := &block{
		view:      event.View,
		blockHash: createDummyBlockHash(),
		height:    event.TipBlockHeight + 1,
		qc:        event.QC,
	}

	// Broadcast the block to all validators.
	for _, validator := range node.validatorNodes {
		go validator.ProcessBlock(block)
	}
}

func (node *validatorNode) handleTimeoutQCConstructionEvent(event *FastHotStuffEvent) {
	node.lock.Lock()
	defer node.lock.Unlock()

	if !node.isBlockProposer {
		return
	}

	// Skip if the view from the event is stale. This can happen if the node
	// has advances to the next view before the block is processed.
	if node.eventLoop.currentView != event.View {
		return
	}

	block := &block{
		view:        event.View,
		blockHash:   createDummyBlockHash(),
		height:      event.TipBlockHeight + 1,
		aggregateQC: event.AggregateQC,
	}

	// Broadcast the block to all validators.
	for _, validator := range node.validatorNodes {
		go validator.ProcessBlock(block)
	}
}

func (node *validatorNode) Stop() {
	node.eventLoop.Stop()
	node.quit <- struct{}{}
}
