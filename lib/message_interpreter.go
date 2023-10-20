package lib

// TODO: ################################
// 	Remove this, components will have handlers individually. Maybe the interpreter will have a bird's eye view of all messages.
func (srv *Server) _handlePeerMessages(serverMessage *ServerMessage) {
	// Handle all non-control message types from our Peers.
	switch msg := serverMessage.Msg.(type) {
	// Messages sent among peers.
	case *MsgDeSoGetHeaders:
		srv._handleGetHeaders(serverMessage.Peer, msg)
	case *MsgDeSoHeaderBundle:
		srv._handleHeaderBundle(serverMessage.Peer, msg)
	case *MsgDeSoGetBlocks:
		srv._handleGetBlocks(serverMessage.Peer, msg)
	case *MsgDeSoBlock:
		srv._handleBlock(serverMessage.Peer, msg)
	case *MsgDeSoGetSnapshot:
		srv._handleGetSnapshot(serverMessage.Peer, msg)
	case *MsgDeSoSnapshotData:
		srv._handleSnapshot(serverMessage.Peer, msg)
	case *MsgDeSoGetTransactions:
		srv._handleGetTransactions(serverMessage.Peer, msg)
	case *MsgDeSoTransactionBundle:
		srv._handleTransactionBundle(serverMessage.Peer, msg)
	case *MsgDeSoTransactionBundleV2:
		srv._handleTransactionBundleV2(serverMessage.Peer, msg)
	case *MsgDeSoMempool:
		srv._handleMempool(serverMessage.Peer, msg)
	case *MsgDeSoInv:
		srv._handleInv(serverMessage.Peer, msg)
	}
}
