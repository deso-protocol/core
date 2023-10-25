package lib

type Controller interface {
	Init(controllers []Controller)
	Start()
	Stop()
	GetType() ControllerType
}

type ControllerType int

const (
	ControllerTypeSync ControllerType = iota
	ControllerTypeConsensus
	ControllerTypeSteady
	ControllerTypeSnapshot
	ControllerTypeStats
	ControllerTypeVersion
)
