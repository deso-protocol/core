package lib

type Manager interface {
	Init(managers []Manager)
	Start()
	Stop()
	GetType() ManagerType
}

type ManagerType int

const (
	ManagerTypeSync ManagerType = iota
	ManagerTypeConsensus
	ManagerTypeSteady
	ManagerTypeSnapshot
	ManagerTypeStats
	ManagerTypeVersion
)
