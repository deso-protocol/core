package lib

func (bav *UtxoView) GetStakeLockupEpochDuration(snapshotAtEpochNumber uint64) uint64 {
	if snapshotAtEpochNumber > 0 {
		// TODO: Return the SnapshotGlobalParamsEntry.StakeLockupEpochDuration if set.
	} else if bav.GlobalParamsEntry.StakeLockupEpochDuration != uint64(0) {
		// Return the CurrentGlobalParamsEntry.StakeLockupEpochDuration if set.
		return bav.GlobalParamsEntry.StakeLockupEpochDuration
	}
	// Return the DefaultStakeLockupEpochDuration.
	return bav.Params.DefaultStakeLockupEpochDuration
}

func (bav *UtxoView) GetValidatorJailEpochDuration(snapshotAtEpochNumber uint64) uint64 {
	if snapshotAtEpochNumber > 0 {
		// TODO: Return the SnapshotGlobalParamsEntry.ValidatorJailEpochDuration if set.
	} else if bav.GlobalParamsEntry.ValidatorJailEpochDuration != uint64(0) {
		// Return the CurrentGlobalParamsEntry.ValidatorJailEpochDuration if set.
		return bav.GlobalParamsEntry.ValidatorJailEpochDuration
	}
	// Return the DefaultValidatorJailEpochDuration.
	return bav.Params.DefaultValidatorJailEpochDuration
}
