package lib

import "github.com/deso-protocol/core/bls"

// RNIndexId is a custom string type used for identifying different types of remote node indices.
type RNIndexId string

// Constants for different types of remote node indices.
const (
	RNIndexId_Validator              RNIndexId = "VALIDATOR"
	RNIndexId_ValidatorAttempted     RNIndexId = "VALIDATOR_ATTEMPTED"
	RNIndexId_NonValidator_Outbound  RNIndexId = "NONVALIDATOR_OUTBOUND"
	RNIndexId_NonValidator_Inbound   RNIndexId = "NONVALIDATOR_INBOUND"
	RNIndexId_NonValidator_Attempted RNIndexId = "NONVALIDATOR_ATTEMPTED"
)

// RemoteNodeIndexer is a structure that holds information about all remote nodes and their indices.
type RemoteNodeIndexer struct {
	// AllRemoteNodes is a map storing all remote nodes by their IDs.
	AllRemoteNodes map[RemoteNodeId]*RemoteNode

	// Indices for various types of remote nodes.
	ValidatorIndex             *RemoteNodeIndex[bls.PublicKey]
	ValidatorAttemptedIndex    *RemoteNodeIndex[bls.PublicKey]
	NonValidatorOutboundIndex  *RemoteNodeIndex[RemoteNodeId]
	NonValidatorInboundIndex   *RemoteNodeIndex[RemoteNodeId]
	NonValidatorAttemptedIndex *RemoteNodeIndex[RemoteNodeId]

	// RemoteNodeToIndexIdList maps remote nodes to their corresponding index IDs.
	RemoteNodeToIndexIdList map[*RemoteNode][]RNIndexId

	RemoteNodeToIndexRemoveFuncList map[*RemoteNode][]RemoteNodeIndexRemoveFunc
}

// NewRemoteNodeIndexer initializes and returns a new instance of RemoteNodeIndexer.
func NewRemoteNodeIndexer() *RemoteNodeIndexer {
	rni := &RemoteNodeIndexer{
		AllRemoteNodes:          make(map[RemoteNodeId]*RemoteNode),
		RemoteNodeToIndexIdList: make(map[*RemoteNode][]RNIndexId),
	}

	// Initializing various indices with their respective types and update callback.
	rni.ValidatorIndex = NewRemoteNodeIndex[bls.PublicKey](RNIndexId_Validator, rni.updateCallback)
	rni.ValidatorAttemptedIndex = NewRemoteNodeIndex[bls.PublicKey](RNIndexId_ValidatorAttempted, rni.updateCallback)
	rni.NonValidatorOutboundIndex = NewRemoteNodeIndex[RemoteNodeId](RNIndexId_NonValidator_Outbound, rni.updateCallback)
	rni.NonValidatorInboundIndex = NewRemoteNodeIndex[RemoteNodeId](RNIndexId_NonValidator_Inbound, rni.updateCallback)
	rni.NonValidatorAttemptedIndex = NewRemoteNodeIndex[RemoteNodeId](RNIndexId_NonValidator_Attempted, rni.updateCallback)
	return rni
}

// Getter methods for accessing the different indices.
func (rni *RemoteNodeIndexer) GetValidatorIndex() RemoteNodeIndexInterface[bls.PublicKey] {
	return rni.ValidatorIndex
}

func (rni *RemoteNodeIndexer) GetValidatorAttemptedIndex() RemoteNodeIndexInterface[bls.PublicKey] {
	return rni.ValidatorAttemptedIndex
}

func (rni *RemoteNodeIndexer) GetNonValidatorOutboundIndex() RemoteNodeIndexInterface[RemoteNodeId] {
	return rni.NonValidatorOutboundIndex
}

func (rni *RemoteNodeIndexer) GetNonValidatorInboundIndex() RemoteNodeIndexInterface[RemoteNodeId] {
	return rni.NonValidatorInboundIndex
}

func (rni *RemoteNodeIndexer) GetNonValidatorAttemptedIndex() RemoteNodeIndexInterface[RemoteNodeId] {
	return rni.NonValidatorAttemptedIndex
}

// Getter methods for AllRemoteNodes
func (rni *RemoteNodeIndexer) GetRemoteNodeFromPeer(peer *Peer) *RemoteNode {
	if peer == nil {
		return nil
	}

	id := peer.ID
	attemptId := peer.AttemptId()
	remoteNodeId := NewRemoteNodeId(id, attemptId)

	rn, ok := rni.AllRemoteNodes[remoteNodeId]
	if !ok {
		return nil
	}
	return rn
}

func (rni *RemoteNodeIndexer) SetRemoteNode(rn *RemoteNode) {
	if rn == nil || EqualsRemoteNodeNoId(rn.GetId()) {
		return
	}

	rni.AllRemoteNodes[rn.GetId()] = rn
}

func (rni *RemoteNodeIndexer) RemoveRemoteNode(rn *RemoteNode) {
	if rn == nil || EqualsRemoteNodeNoId(rn.GetId()) {
		return
	}

	delete(rni.AllRemoteNodes, rn.GetId())
	if _, ok := rni.RemoteNodeToIndexRemoveFuncList[rn]; !ok {
		return
	}

	for _, removeFunc := range rni.RemoteNodeToIndexRemoveFuncList[rn] {
		if removeFunc == nil {
			continue
		}
		removeFunc()
	}
}

// updateCallback is invoked when a node is added or removed from an index.
func (rni *RemoteNodeIndexer) updateCallback(id RNIndexId, node *RemoteNode, isAdd bool, removeFunc RemoteNodeIndexRemoveFunc) {
	if isAdd {
		rni.RemoteNodeToIndexIdList[node] = append(rni.RemoteNodeToIndexIdList[node], id)
		rni.RemoteNodeToIndexRemoveFuncList[node] = append(rni.RemoteNodeToIndexRemoveFuncList[node], removeFunc)
	} else {
		var indexId RNIndexId
		pos := 0

		for pos, indexId = range rni.RemoteNodeToIndexIdList[node] {
			if indexId == id {
				rni.RemoteNodeToIndexIdList[node] = append(rni.RemoteNodeToIndexIdList[node][:pos], rni.RemoteNodeToIndexIdList[node][pos+1:]...)
				break
			}
		}

		rni.RemoteNodeToIndexRemoveFuncList[node] = append(rni.RemoteNodeToIndexRemoveFuncList[node][:pos], rni.RemoteNodeToIndexRemoveFuncList[node][pos+1:]...)
	}
}

// RemoteNodeIndexInterface defines the methods for a remote node index.
type RemoteNodeIndexInterface[Key comparable] interface {
	GetId() RNIndexId
	Add(key Key, node *RemoteNode)
	Remove(key Key)
	Get(key Key) (*RemoteNode, bool)
	GetRandom() (*RemoteNode, bool)
	GetIndex() map[Key]*RemoteNode
	GetAll() []*RemoteNode
}

// RemoteNodeIndex holds an index of remote nodes by a specific key type.
type RemoteNodeIndex[Key comparable] struct {
	Id             RNIndexId
	Index          map[Key]*RemoteNode
	updateCallback RemoteNodeIndexCallback
}

// RemoteNodeIndexRemoveFunc is a function type for removal of a RemoteNode from the Index.
type RemoteNodeIndexRemoveFunc func()

// RemoteNodeIndexCallback is a function type for update callbacks.
type RemoteNodeIndexCallback func(id RNIndexId, node *RemoteNode, isAdd bool, removeFunc RemoteNodeIndexRemoveFunc)

// NewRemoteNodeIndex creates and returns a new RemoteNodeIndex.
func NewRemoteNodeIndex[Key comparable](id RNIndexId, updateCallback RemoteNodeIndexCallback) *RemoteNodeIndex[Key] {
	return &RemoteNodeIndex[Key]{
		Id:             id,
		Index:          make(map[Key]*RemoteNode),
		updateCallback: updateCallback,
	}
}

// Implementations of the RemoteNodeIndexInterface methods.
func (rni *RemoteNodeIndex[Key]) GetId() RNIndexId {
	return rni.Id
}

func (rni *RemoteNodeIndex[Key]) Add(key Key, node *RemoteNode) {
	rni.Index[key] = node

	// Define the remove function
	removeFunc := func() {
		if _, ok := rni.Index[key]; !ok {
			return
		}
		delete(rni.Index, key)
	}

	if rni.updateCallback != nil {
		rni.updateCallback(rni.Id, node, true, removeFunc)
	}
}

func (rni *RemoteNodeIndex[Key]) Remove(key Key) {
	rn, ok := rni.Index[key]
	if !ok {
		return
	}
	delete(rni.Index, key)
	if rni.updateCallback != nil {
		rni.updateCallback(rni.Id, rn, false, nil)
	}
}

func (rni *RemoteNodeIndex[Key]) Get(key Key) (*RemoteNode, bool) {
	elem, ok := rni.Index[key]
	return elem, ok
}

func (rni *RemoteNodeIndex[Key]) GetRandom() (*RemoteNode, bool) {
	if len(rni.Index) == 0 {
		return nil, false
	}

	var node *RemoteNode
	for _, node = range rni.Index {
		break
	}
	return node, true
}

func (rni *RemoteNodeIndex[Key]) GetIndex() map[Key]*RemoteNode {
	index := make(map[Key]*RemoteNode)
	for key, node := range rni.Index {
		index[key] = node
	}
	return index
}

func (rni *RemoteNodeIndex[Key]) GetAll() []*RemoteNode {
	var nodes []*RemoteNode
	for _, node := range rni.Index {
		nodes = append(nodes, node)
	}
	return nodes
}
