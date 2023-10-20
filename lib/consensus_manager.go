package lib

import (
	"github.com/deso-protocol/core/consensus"
	"github.com/golang/glog"
	"sync/atomic"
)

type ConsensusManager struct {
}

// TODO: ################################
// 	Move this to Consensus Manager
func (cm *ConsensusManager) _handleFastHostStuffBlockProposal(event *consensus.ConsensusEvent) {
	// The consensus module has signaled that we can propose a block at a certain block
	// height. We construct the block and broadcast it here:
	// 1. Verify that the block height we want to propose at is valid
	// 2. Get a QC from the consensus module
	// 3. Iterate over the top n transactions from the mempool
	// 4. Construct a block with the QC and the top n transactions from the mempool
	// 5. Sign the block
	// 6. Process the block locally
	//   - This will connect the block to the blockchain, remove the transactions from the
	//   - mempool, and process the vote in the consensus module
	// 7. Broadcast the block to the network
}

// TODO: ################################
// 	Move this to Consensus Manager
func (cm *ConsensusManager) _handleFastHostStuffVote(event *consensus.ConsensusEvent) {
	// The consensus module has signaled that we can vote on a block. We construct and
	// broadcast the vote here:
	// 1. Verify that the block height we want to vote on is valid
	// 2. Construct the vote message
	// 3. Process the vote in the consensus module
	// 4. Broadcast the timeout msg to the network
}

// TODO: ################################
// 	Move this to Consensus Manager
func (cm *ConsensusManager) _handleFastHostStuffTimeout(event *consensus.ConsensusEvent) {
	// The consensus module has signaled that we have timed out for a view. We construct and
	// broadcast the timeout here:
	// 1. Verify the block height and view we want to timeout on are valid
	// 2. Construct the timeout message
	// 3. Process the timeout in the consensus module
	// 4. Broadcast the timeout msg to the network
}

// TODO: ################################
// 	Move this to Consensus Manager
func (cm *ConsensusManager) _handleFastHostStuffConsensusEvent(event *consensus.ConsensusEvent) {
	switch event.EventType {
	case consensus.ConsensusEventTypeBlockProposal:
		srv._handleFastHostStuffBlockProposal(event)
	case consensus.ConsensusEventTypeVote:
		srv._handleFastHostStuffVote(event)
	case consensus.ConsensusEventTypeTimeout:
		srv._handleFastHostStuffTimeout(event)
	}
}

// TODO: ################################
// 	Move this to Consensus Manager
// _startConsensusEventLoop contains the top-level event loop to run both the PoW and PoS consensus. It is
// single-threaded to ensure that concurrent event do not conflict with each other. It's role is to guarantee
// single threaded processing and act as an entry point for consensus events. It does minimal validation on its
// own.
//
// For the PoW consensus:
// - It listens to all peer messages from the network and handles them as they come in. This includes
// control messages from peer, proposed blocks from peers, votes/timeouts, block requests, mempool
// requests from syncing peers
//
// For the PoS consensus:
// - It listens to all peer messages from the network and handles them as they come in. This includes
// control messages from peer, proposed blocks from peers, votes/timeouts, block requests, mempool
// requests from syncing peers
// - It listens to consensus events from the Fast HostStuff consensus engine. The consensus signals when
// it's ready to vote, timeout, or propose a block.
func (cm *ConsensusManager) _startConsensus() {
	for {
		// This is used instead of the shouldQuit control message exist mechanism below. shouldQuit will be true only
		// when all incoming messages have been processed, on the other hand this shutdown will quit immediately.
		if atomic.LoadInt32(&srv.shutdown) >= 1 {
			break
		}

		select {
		case consensusEvent := <-srv.fastHotStuffConsensus.ConsensusEvents:
			{
				glog.Infof("Server._startConsensus: Received consensus event for block height: %v", consensusEvent.BlockHeight)
				srv._handleFastHostStuffConsensusEvent(consensusEvent)
			}

			// TODO: ################################
			// 	THIS SHOULD BE IN SERVER / CONNECTION_MANAGER BIG TIME.
		case serverMessage := <-srv.incomingMessages:
			{
				// There is an incoming network message from a peer.

				glog.V(2).Infof("Server._startConsensus: Handling message of type %v from Peer %v",
					serverMessage.Msg.GetMsgType(), serverMessage.Peer)

				// If the message is an addr message we handle it independent of whether or
				// not the BitcoinManager is synced.
				if serverMessage.Msg.GetMsgType() == MsgTypeAddr {
					srv._handleAddrMessage(serverMessage.Peer, serverMessage.Msg.(*MsgDeSoAddr))
					continue
				}
				// If the message is a GetAddr message we handle it independent of whether or
				// not the BitcoinManager is synced.
				if serverMessage.Msg.GetMsgType() == MsgTypeGetAddr {
					srv._handleGetAddrMessage(serverMessage.Peer, serverMessage.Msg.(*MsgDeSoGetAddr))
					continue
				}

				srv._handlePeerMessages(serverMessage)

				// Always check for and handle control messages regardless of whether the
				// BitcoinManager is synced. Note that we filter control messages out in a
				// Peer's inHandler so any control message we get at this point should be bona fide.
				shouldQuit := srv._handleControlMessages(serverMessage)
				if shouldQuit {
					break
				}
			}

		}
	}

	// If we broke out of the select statement then it's time to allow things to
	// clean up.
	srv.waitGroup.Done()
	glog.V(2).Info("Server.Start: Server done")
}
