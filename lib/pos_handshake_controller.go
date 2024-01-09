package lib

import (
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/core/bls"
	"github.com/golang/glog"
	"math"
)

// TODO: Replace this
func getActiveValidators() map[bls.PublicKey]*ValidatorEntry {
	// TODO: replace with a getter to retrieve all active validators.
	activeValidators := []*ValidatorEntry{}
	allValidatorsMap := make(map[bls.PublicKey]*ValidatorEntry)
	for _, validator := range activeValidators {
		pk := validator.VotingPublicKey
		if pk == nil {
			continue
		}
		allValidatorsMap[*pk] = validator
	}

	return allValidatorsMap
}

type HandshakeController struct {
	rnManager              *RemoteNodeManager
	usedNonces             lru.Cache
	protocolOnProofOfStake func() bool                              // TODO
	getActiveValidators    func() map[bls.PublicKey]*ValidatorEntry // TODO
}

func NewHandshakeController(rnManager *RemoteNodeManager) *HandshakeController {

	vm := &HandshakeController{
		rnManager:              rnManager,
		usedNonces:             lru.NewCache(1000),
		protocolOnProofOfStake: func() bool { return false },
	}

	return vm
}

func (hc *HandshakeController) InitiateHandshake(rn *RemoteNode) {

	nonce := uint64(RandInt64(math.MaxInt64))
	if err := rn.InitiateHandshake(nonce); err != nil {
		glog.Errorf("RemoteNode.InitiateHandshake: Error initiating handshake: %v", err)
		hc.rnManager.Disconnect(rn)
	}
}

func (hc *HandshakeController) handlePoSHandshakePeerMessage(remoteNode *RemoteNode) {
	if !hc.protocolOnProofOfStake() {
		return
	}

	// Make sure the peer is on the right proof of stake version
	if remoteNode.GetNegotiatedProtocolVersion() != ProtocolVersion2 {
		// Disconnect the peer because we only accept validators running proof of stake.
		hc.rnManager.Disconnect(remoteNode)
		return
	}

	// Get all active validators and see if the peer is one of them.
	activeValidators := hc.getActiveValidators()
	validatorPk := remoteNode.GetValidatorPublicKey()
	if validatorPk == nil {
		// Disconnect the peer because we only accept validators running proof of stake.
		hc.rnManager.Disconnect(remoteNode)
		return
	}

	// If there's already a validator connected with the same public key, disconnect the peer.
	if _, ok := hc.rnManager.GetRemoteNodeIndexer().GetValidatorIndex().Get(validatorPk.Serialize()); ok {
		hc.rnManager.Disconnect(remoteNode)
		return
	}

	// If the peer is not an active validator, there is nothing else to check so return.
	if _, ok := activeValidators[*validatorPk]; !ok {
		return
	}
}

func (hc *HandshakeController) _handleHandshakePeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypePeerHandshakeComplete {
		return
	}

	// Get the handshake information of this peer.
	remoteNode := hc.rnManager.GetRemoteNodeFromPeer(origin)
	if remoteNode == nil {
		return
	}

	if hc.protocolOnProofOfStake() {
		hc.handlePoSHandshakePeerMessage(remoteNode)
	}
	hc.rnManager.ProcessCompletedHandshake(remoteNode)
}

func (hc *HandshakeController) _handleVersionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVersion {
		return
	}

	rn := hc.rnManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		return
	}

	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		hc.rnManager.Disconnect(rn)
		return
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if hc.usedNonces.Contains(msgNonce) {
		hc.usedNonces.Delete(msgNonce)
		glog.Errorf("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce collision", origin.ID)
		hc.rnManager.Disconnect(rn)
		return
	}

	responseNonce := uint64(RandInt64(math.MaxInt64))
	if err := rn.HandleVersionMessage(verMsg, responseNonce); err != nil {
		glog.Errorf("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"error handling version message: %v", origin.ID, err)
		hc.rnManager.Disconnect(rn)
		return

	}
	hc.usedNonces.Add(responseNonce)
}

func (hc *HandshakeController) _handleVerackMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVerack {
		return
	}

	rn := hc.rnManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		return
	}

	var vrkMsg *MsgDeSoVerack
	var ok bool
	if vrkMsg, ok = desoMsg.(*MsgDeSoVerack); !ok {
		hc.rnManager.Disconnect(rn)
		return
	}

	if !ok {
		glog.Errorf("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce not found for peer", origin.ID)
		rn.Disconnect()
		return
	}

	if err := rn.HandleVerackMessage(vrkMsg); err != nil {
		glog.Errorf("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"error handling verack message: %v", origin.ID, err)
		hc.rnManager.Disconnect(rn)
		return
	}
	return
}
