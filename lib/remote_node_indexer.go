package lib

import (
	"github.com/deso-protocol/core/bls"
	"github.com/deso-protocol/core/collections"
)

// RemoteNodeIndexer is a structure that holds information about all remote nodes and their indices.
type RemoteNodeIndexer struct {
	// AllRemoteNodes is a map storing all remote nodes by their IDs.
	AllRemoteNodes *collections.ConcurrentMap[RemoteNodeId, *RemoteNode]

	// Indices for various types of remote nodes.
	ValidatorIndex            *collections.ConcurrentMap[bls.SerializedPublicKey, *RemoteNode]
	NonValidatorOutboundIndex *collections.ConcurrentMap[RemoteNodeId, *RemoteNode]
	NonValidatorInboundIndex  *collections.ConcurrentMap[RemoteNodeId, *RemoteNode]
}

// NewRemoteNodeIndexer initializes and returns a new instance of RemoteNodeIndexer.
func NewRemoteNodeIndexer() *RemoteNodeIndexer {
	rni := &RemoteNodeIndexer{
		AllRemoteNodes:            collections.NewConcurrentMap[RemoteNodeId, *RemoteNode](),
		ValidatorIndex:            collections.NewConcurrentMap[bls.SerializedPublicKey, *RemoteNode](),
		NonValidatorOutboundIndex: collections.NewConcurrentMap[RemoteNodeId, *RemoteNode](),
		NonValidatorInboundIndex:  collections.NewConcurrentMap[RemoteNodeId, *RemoteNode](),
	}

	return rni
}

// Getter methods for accessing the different indices.
func (rni *RemoteNodeIndexer) GetAllRemoteNodes() *collections.ConcurrentMap[RemoteNodeId, *RemoteNode] {
	return rni.AllRemoteNodes
}

func (rni *RemoteNodeIndexer) GetValidatorIndex() *collections.ConcurrentMap[bls.SerializedPublicKey, *RemoteNode] {
	return rni.ValidatorIndex
}

func (rni *RemoteNodeIndexer) GetNonValidatorOutboundIndex() *collections.ConcurrentMap[RemoteNodeId, *RemoteNode] {
	return rni.NonValidatorOutboundIndex
}

func (rni *RemoteNodeIndexer) GetNonValidatorInboundIndex() *collections.ConcurrentMap[RemoteNodeId, *RemoteNode] {
	return rni.NonValidatorInboundIndex
}
