package lib

type PaceMakerTimeoutSignal struct {
	TimedOutView uint64
}

// PaceMaker is responsible for the following:
// - Tracking the current consensus view number
// - Tracking the current view's view duration
// - Accepting an incoming block and updating the current view number where necessary
// - Emitting an event when the current view has timed out
type PaceMaker struct {
	TimedOutViews <-chan PaceMakerTimeoutSignal
}

func NewPaceMaker() *PaceMaker {
	return &PaceMaker{
		TimedOutViews: make(chan PaceMakerTimeoutSignal),
	}
}

// Runs the pace maker's internal timer that regulates consensus view durations, and
// handles exponential backoff, and signals when a view has timed out.
func (pm *PaceMaker) Start() {
	// TODO
}

func (pm *PaceMaker) Stop() {
	// TODO
}

// Sets the current view and resets the internal timer.
func (pm *PaceMaker) SetView(viewNumber uint64) {
	// TODO
}

func (pm *PaceMaker) GetView() uint64 {
	// TODO
	return 0
}

func (pm *PaceMaker) SetBaseTimeoutDuration(timeoutDurationNumSecs uint64) {
	// TODO
}

// BlockAccepted is called when an incoming block has been validated and added to the blockchain tip.
// It updates the view, and resets the internal timer.
func (pm *PaceMaker) BlockAccepted(blockHeader *MsgDeSoHeader) error {
	// TODO
	return nil
}
