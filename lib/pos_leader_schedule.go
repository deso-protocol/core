package lib

import (
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

func (bav *UtxoView) GenerateLeaderSchedule() ([]*ValidatorEntry, error) {
	numValidators := 100 // bav.Params.PoSLeaderScheduleNumValidators

	// Retrieve CurrentRandomSeedHash.
	currentRandomSeedHash, err := bav.GetCurrentRandomSeedHash()
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error retrieving CurrentRandomSeedHash: ")
	}

	// Retrieve top, active validators ordered by stake.
	validatorEntries, err := bav.GetTopActiveValidatorsByStake(int(numValidators))
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error retrieving top ValidatorEntries: ")
	}
	if len(validatorEntries) == 0 {
		return []*ValidatorEntry{}, nil
	}

	// Sum TotalStakeAmountNanos.
	totalStakeAmountNanos := uint256.NewInt()
	for _, validatorEntry := range validatorEntries {
		totalStakeAmountNanos, err = SafeUint256().Add(totalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
		if err != nil {
			return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error summing TotalStakeAmountNanos: ")
		}
	}

	// Pseudocode for leader-selection algorithm:
	// While len(LeaderSchedule) < len(ValidatorEntries)
	//   RandomUint256 %= TotalStakeAmountNanos.
	//   For each ValidatorEntry...
	//   Skip if ValidatorEntry.TotalStakeAmountNanos is zero.
	//   Skip if ValidatorEntry has already been added to the leader schedule.
	//   If ValidatorEntry.TotalStakeAmountNanos >= RandomUint256:
	//     Add ValidatorEntry to LeaderSchedule.
	//     TotalStakeAmountNanos -= ValidatorEntry.TotalStakeAmountNanos.
	var leaderSchedule []*ValidatorEntry

	// We also track a set of ValidatorPKIDs that have already been
	// added to the LeaderSchedule so that we can skip them when
	// iterating over ValidatorEntries in O(1) time.
	leaderSchedulePKIDs := NewSet([]*PKID{})

	for len(leaderSchedule) < len(validatorEntries) {
		// Take RandomUint256 % TotalStakeAmountNanos.
		randomUint256 := uint256.NewInt().Mod(currentRandomSeedHash.ToUint256(), totalStakeAmountNanos)

		// Keep track of the stake seen so far in this loop.
		sumStakeAmountNanos := uint256.NewInt()

		for _, validatorEntry := range validatorEntries {
			// Skip if ValidatorEntry has already been added to the leader schedule.
			if leaderSchedulePKIDs.Includes(validatorEntry.ValidatorPKID) {
				continue
			}

			// Sum the ValidatorEntry.TotalStakeAmountNanos to the stake seen so far.
			sumStakeAmountNanos, err = SafeUint256().Add(sumStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
			if err != nil {
				return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error summing TotalStakeAmountNanos: ")
			}

			// If the sum of the stake seen so far is less than the RandomUint256, skip this validator.
			if sumStakeAmountNanos.Lt(randomUint256) {
				continue
			}

			// If we get to this point, the current validator is the
			// one we should add to the leader schedule next.

			// Add the current ValidatorEntry to the leaderSchedule.
			leaderSchedule = append(leaderSchedule, validatorEntry)
			leaderSchedulePKIDs.Add(validatorEntry.ValidatorPKID)

			// Subtract the ValidatorEntry.TotalStakeAmountNanos from the TotalStakeAmountNanos.
			totalStakeAmountNanos, err = SafeUint256().Sub(totalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
			if err != nil {
				return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error subtracting TotalStakeAmountNanos: ")
			}
		}
	}

	return leaderSchedule, nil
}
