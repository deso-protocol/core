package consensus

import "time"

type MockFastHotStuffEventLoop struct {
	OnGetEvents               func() chan *FastHotStuffEvent
	OnInit                    func(time.Duration, time.Duration, BlockWithValidatorList, []BlockWithValidatorList) error
	OnGetCurrentView          func() uint64
	OnAdvanceViewOnTimeout    func() (uint64, error)
	OnProcessTipBlock         func(BlockWithValidatorList, []BlockWithValidatorList) error
	OnUpdateSafeBlocks        func([]BlockWithValidatorList) error
	OnProcessValidatorVote    func(VoteMessage) error
	OnProcessValidatorTimeout func(TimeoutMessage) error
	OnStart                   func()
	OnStop                    func()
	OnIsInitialized           func() bool
	OnIsRunning               func() bool
}

func (fc *MockFastHotStuffEventLoop) GetEvents() chan *FastHotStuffEvent {
	return fc.OnGetEvents()
}
func (fc *MockFastHotStuffEventLoop) Init(crankTimerInterval time.Duration, timeoutBaseDuration time.Duration, tip BlockWithValidatorList, safeBlocks []BlockWithValidatorList) error {
	return fc.OnInit(crankTimerInterval, timeoutBaseDuration, tip, safeBlocks)
}

func (fc *MockFastHotStuffEventLoop) GetCurrentView() uint64 {
	return fc.OnGetCurrentView()
}

func (fc *MockFastHotStuffEventLoop) AdvanceViewOnTimeout() (uint64, error) {
	return fc.OnAdvanceViewOnTimeout()
}

func (fc *MockFastHotStuffEventLoop) ProcessTipBlock(tipBlock BlockWithValidatorList, safeBlocks []BlockWithValidatorList) error {
	return fc.OnProcessTipBlock(tipBlock, safeBlocks)
}

func (fc *MockFastHotStuffEventLoop) UpdateSafeBlocks(safeBlocks []BlockWithValidatorList) error {
	return fc.OnUpdateSafeBlocks(safeBlocks)
}

func (fc *MockFastHotStuffEventLoop) ProcessValidatorVote(vote VoteMessage) error {
	return fc.OnProcessValidatorVote(vote)
}

func (fc *MockFastHotStuffEventLoop) ProcessValidatorTimeout(timeout TimeoutMessage) error {
	return fc.OnProcessValidatorTimeout(timeout)
}

func (fc *MockFastHotStuffEventLoop) Start() {
	fc.OnStart()
}

func (fc *MockFastHotStuffEventLoop) Stop() {
	fc.OnStop()
}

func (fc *MockFastHotStuffEventLoop) IsInitialized() bool {
	return fc.OnIsInitialized()
}

func (fc *MockFastHotStuffEventLoop) IsRunning() bool {
	return fc.OnIsRunning()
}