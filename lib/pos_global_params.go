package lib

func (bav *UtxoView) GetStakeLockupEpochDuration() uint64 {
	if bav.GlobalParamsEntry.StakeLockupEpochDuration != uint64(0) {
		return bav.GlobalParamsEntry.StakeLockupEpochDuration
	}
	return bav.Params.DefaultStakeLockupEpochDuration
}

func (bav *UtxoView) GetValidatorJailEpochDuration() uint64 {
	if bav.GlobalParamsEntry.ValidatorJailEpochDuration != uint64(0) {
		return bav.GlobalParamsEntry.ValidatorJailEpochDuration
	}
	return bav.Params.DefaultValidatorJailEpochDuration
}
