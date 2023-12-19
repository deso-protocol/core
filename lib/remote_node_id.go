package lib

const (
	RemoteNodeIdNoPeer    = 0
	RemoteNodeIdNoAttempt = 0
)

type RemoteNodeId struct {
	peerId    uint64
	attemptId uint64
}

func (id RemoteNodeId) GetIds() (peerId uint64, attemptId uint64) {
	return id.peerId, id.attemptId
}

func NewRemoteNodeId(peerId uint64, attemptId uint64) RemoteNodeId {
	return RemoteNodeId{
		peerId:    peerId,
		attemptId: attemptId,
	}
}

func NewRemoteNodeOutboundId(peerId uint64, attemptId uint64) RemoteNodeId {
	return NewRemoteNodeId(peerId, attemptId)
}

func NewRemoteNodeInboundId(peerId uint64) RemoteNodeId {
	return RemoteNodeId{
		peerId:    peerId,
		attemptId: RemoteNodeIdNoAttempt,
	}
}

func NewRemoteNodeAttemptedId(attemptId uint64) RemoteNodeId {
	return RemoteNodeId{
		peerId:    RemoteNodeIdNoPeer,
		attemptId: attemptId,
	}
}

func NewRemoteNodeNoId() RemoteNodeId {
	return RemoteNodeId{
		peerId:    RemoteNodeIdNoPeer,
		attemptId: RemoteNodeIdNoAttempt,
	}
}

func CompareRemoteNodeId(id1 RemoteNodeId, id2 RemoteNodeId) (_equal bool) {
	peerId1, attemptId1 := id1.GetIds()
	peerId2, attemptId2 := id2.GetIds()
	return peerId1 == peerId2 && attemptId1 == attemptId2
}

func EqualsRemoteNodeNoId(id RemoteNodeId) bool {
	return CompareRemoteNodeId(id, NewRemoteNodeNoId())
}
