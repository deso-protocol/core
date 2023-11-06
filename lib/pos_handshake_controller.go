package lib

import (
	"github.com/decred/dcrd/lru"
	"github.com/deso-protocol/core/bls"
	"github.com/golang/glog"
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
	rniManager             *RemoteNodeIndexerManager
	usedNonces             lru.Cache
	protocolOnProofOfStake func() bool                              // TODO
	getActiveValidators    func() map[bls.PublicKey]*ValidatorEntry // TODO
}

func NewHandshakeController(rniManager *RemoteNodeIndexerManager) *HandshakeController {

	vm := &HandshakeController{
		rniManager: rniManager,
		usedNonces: lru.NewCache(1000),
	}

	return vm
}

func (hc *HandshakeController) handlePoSHandshakePeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if !hc.protocolOnProofOfStake() {
		return
	}

	// Get the handshake information of this peer.
	rn := hc.rniManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		return
	}

	handshakeMetadata := rn.GetHandshakeMetadata()
	// Make sure the peer is on the right proof of stake version
	if handshakeMetadata.NegotiatedProtocolVersion() != ProtocolVersion2 {
		// Disconnect the peer because we only accept validators running proof of stake.
		hc.rniManager.Disconnect(rn)
		//# cc.removeValidator(origin)
		return
	}

	// Get all active validators and see if the peer is one of them.
	activeValidators := hc.getActiveValidators()
	validatorPk := handshakeMetadata.GetValidatorPublicKey()

	// If there's already a validator connected with the same public key, disconnect the peer.
	if _, ok := hc.rniManager.GetRemoteNodeIndexer().GetValidatorIndex().Get(validatorPk); ok {
		hc.rniManager.Disconnect(rn)
		return
	}

	// If the peer is not an active validator, there is nothing else to check so return.
	if _, ok := activeValidators[validatorPk]; !ok {
		return
	}

	// So we know this peer is an active validator. Add it to the validator index.
	hc.rniManager.SetValidator(validatorPk, rn)
}

func (hc *HandshakeController) _handleHandshakePeerMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeHandshakePeer {
		return
	}

	if hc.protocolOnProofOfStake() {
		hc.handlePoSHandshakePeerMessage(origin, desoMsg)
	}
}

func (hc *HandshakeController) _handleVersionMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVersion {
		return
	}

	rn := hc.rniManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		return
	}

	var verMsg *MsgDeSoVersion
	var ok bool
	if verMsg, ok = desoMsg.(*MsgDeSoVersion); !ok {
		hc.rniManager.Disconnect(rn)
		return
	}

	// If we've sent this nonce before then return an error since this is
	// a connection from ourselves.
	msgNonce := verMsg.Nonce
	if hc.usedNonces.Contains(msgNonce) {
		hc.usedNonces.Delete(msgNonce)
		glog.V(1).Infof("HandshakeController._handleVersionMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce collision", origin.ID)
		rn.Disconnect()
		return
	}

	rn.HandleVersionMessage(verMsg, func(versionNonce uint64) {
		hc.usedNonces.Add(versionNonce)
	})
}

func (hc *HandshakeController) _handleVerackMessage(origin *Peer, desoMsg DeSoMessage) {
	if desoMsg.GetMsgType() != MsgTypeVerack {
		return
	}

	rn := hc.rniManager.GetRemoteNodeFromPeer(origin)
	if rn == nil {
		return
	}

	var vrkMsg *MsgDeSoVerack
	var ok bool
	if vrkMsg, ok = desoMsg.(*MsgDeSoVerack); !ok {
		hc.rniManager.Disconnect(rn)
		return
	}

	if !ok {
		glog.V(1).Infof("HandshakeController._handleVerackMessage: Requesting PeerDisconnect for id: (%v) "+
			"nonce not found for peer", origin.ID)
		rn.Disconnect()
		return
	}

	rn.HandleVerackMessage(vrkMsg)
	return
}
