package lib

import (
	"crypto/sha256"

	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

func (bav *UtxoView) GenerateLeaderSchedule(validatorSet []*ValidatorEntry) ([]*PKID, error) {
	// Retrieve CurrentRandomSeedHash.
	currentRandomSeedHash, err := bav.GetCurrentRandomSeedHash()
	if err != nil {
		return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error retrieving CurrentRandomSeedHash: ")
	}

	// Retrieve the LeaderScheduleMaxNumValidators from the current GlobalParams. We are safe to use the current
	// global params because this generates a new leader schedule from the current validator entries, in preparation
	// to snapshot the leader schedule.
	currentGlobalParamsEntry := bav.GetCurrentGlobalParamsEntry()

	validatorEntries := validatorSet
	// If the number of validators is greater than the max number of validators, we need to select the top
	// maxLeaderScheduleNumValidators validators by stake.
	if uint64(len(validatorSet)) > currentGlobalParamsEntry.LeaderScheduleMaxNumValidators {
		validatorEntries = validatorSet[:currentGlobalParamsEntry.LeaderScheduleMaxNumValidators]
	}
	if len(validatorEntries) == 0 {
		return []*PKID{}, nil
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
	// Note this is an O(N^2) algorithm where N is the number of validators we include.
	// While len(LeaderSchedule) < len(ValidatorEntries):
	//   Hash the CurrentRandomSeedHash and generate a new RandomUint256.
	//   Take RandomUint256 modulo TotalStakeAmountNanos.
	//   For each ValidatorEntry:
	//     Skip if ValidatorPKID has already been added to the leader schedule.
	//     If the sum of the ValidatorEntry.TotalStakeAmountNanos seen so far >= RandomUint256:
	//       Add ValidatorPKID to LeaderSchedule.
	//       TotalStakeAmountNanos -= ValidatorEntry.TotalStakeAmountNanos.
	//       Break out of the inner loop.
	var leaderSchedule []*PKID

	// We also track a set of ValidatorPKIDs that have already been
	// added to the LeaderSchedule so that we can skip them when
	// iterating over ValidatorEntries in O(1) time.
	leaderSchedulePKIDs := NewSet([]PKID{})

	for len(leaderSchedule) < len(validatorEntries) {
		// Hash the CurrentRandomSeedHash each iteration. This generates
		// multiple predictable pseudorandom values from the same seed.
		currentRandomSHA256 := sha256.Sum256(currentRandomSeedHash.ToBytes())
		currentRandomSeedHash, err = (&RandomSeedHash{}).FromBytes(currentRandomSHA256[:])
		if err != nil {
			return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error hashing CurrentRandomSeedHash: ")
		}

		// Take RandomUint256 % TotalStakeAmountNanos.
		randomUint256 := uint256.NewInt().Mod(currentRandomSeedHash.ToUint256(), totalStakeAmountNanos)

		// Keep track of the stake seen so far in this loop.
		sumStakeAmountNanos := uint256.NewInt()

		for _, validatorEntry := range validatorEntries {
			// Skip if ValidatorEntry has already been added to the leader schedule.
			if leaderSchedulePKIDs.Includes(*validatorEntry.ValidatorPKID) {
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

			// Add the current ValidatorPKID to the leaderSchedule.
			leaderSchedule = append(leaderSchedule, validatorEntry.ValidatorPKID)
			leaderSchedulePKIDs.Add(*validatorEntry.ValidatorPKID)

			// Subtract the ValidatorEntry.TotalStakeAmountNanos from the TotalStakeAmountNanos.
			totalStakeAmountNanos, err = SafeUint256().Sub(totalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
			if err != nil {
				return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error subtracting TotalStakeAmountNanos: ")
			}

			// The current validator has been added to the leader schedule.
			// Break out of this inner loop, generate a new RandomUint256,
			// and find the next stake-weighted validator to add to the
			// leader schedule.
			break
		}
	}

	return leaderSchedule, nil
}
