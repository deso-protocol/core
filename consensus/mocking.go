package consensus

import "time"

type MockFastHotStuffEventLoop struct {
	onGetEvents               func() chan *FastHotStuffEvent
	onInit                    func(time.Duration, time.Duration, BlockWithValidatorList, []BlockWithValidatorList) error
	onGetCurrentView          func() uint64
	onAdvanceViewOnTimeout    func() (uint64, error)
	onProcessTipBlock         func(BlockWithValidatorList, []BlockWithValidatorList) error
	onProcessValidatorVote    func(VoteMessage) error
	onProcessValidatorTimeout func(TimeoutMessage) error
	onStart                   func()
	onStop                    func()
	onIsInitialized           func() bool
	onIsRunning               func() bool
}

func (fc *MockFastHotStuffEventLoop) GetEvents() chan *FastHotStuffEvent {
	return fc.GetEvents()
}
func (fc *MockFastHotStuffEventLoop) Init(crankTimerInterval time.Duration, timeoutBaseDuration time.Duration, tip BlockWithValidatorList, safeBlocks []BlockWithValidatorList) error {
	return fc.onInit(crankTimerInterval, timeoutBaseDuration, tip, safeBlocks)
}

func (fc *MockFastHotStuffEventLoop) GetCurrentView() uint64 {
	return fc.onGetCurrentView()
}

func (fc *MockFastHotStuffEventLoop) AdvanceViewOnTimeout() (uint64, error) {
	return fc.onAdvanceViewOnTimeout()
}

func (fc *MockFastHotStuffEventLoop) ProcessTipBlock(tipBlock BlockWithValidatorList, safeBlocks []BlockWithValidatorList) error {
	return fc.onProcessTipBlock(tipBlock, safeBlocks)
}

func (fc *MockFastHotStuffEventLoop) ProcessValidatorVote(vote VoteMessage) error {
	return fc.onProcessValidatorVote(vote)
}

func (fc *MockFastHotStuffEventLoop) ProcessValidatorTimeout(timeout TimeoutMessage) error {
	return fc.onProcessValidatorTimeout(timeout)
}

func (fc *MockFastHotStuffEventLoop) Start() {
	fc.onStart()
}

func (fc *MockFastHotStuffEventLoop) Stop() {
	fc.onStop()
}

func (fc *MockFastHotStuffEventLoop) IsInitialized() bool {
	return fc.onIsInitialized()
}

func (fc *MockFastHotStuffEventLoop) IsRunning() bool {
	return fc.onIsRunning()
}
