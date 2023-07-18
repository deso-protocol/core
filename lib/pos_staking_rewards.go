package lib

import (
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
)

func (bav *UtxoView) DistributeStakingRewardsToSnapshotStakes(blockHeight uint64) error {
	// Check if we have switched from PoW to PoS yet. If we have not, then the PoS consensus
	// has not started yet. We don't want to distribute any staking rewards until the PoS consensus begins.
	if blockHeight < uint64(bav.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		return nil
	}

	// Retrieve the SnapshotGlobalParamsEntry.
	snapshotGlobalParamsEntry, err := bav.GetSnapshotGlobalParamsEntry()
	if err != nil {
		return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem retrieving SnapshotGlobalParamsEntry: ")
	}

	totalStakingRewards := bav._placeholderGetStakingRewardsPerEpoch()

	// If the total rewards to pay out are zero, then there's nothing to be done. Exit early here.
	if totalStakingRewards.IsZero() {
		return nil
	}

	// Reward all snapshotted stakes from the current snapshot validator set. This is an O(n) operation
	// that loops through all of the snapshotted stakes and rewards them.
	snapshotStakesToReward, err := bav.GetSnapshotStakesToRewardByStakeAmount(snapshotGlobalParamsEntry.StakingRewardsMaxNumStakes)
	if err != nil {
		return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem retrieving snapshot stakes to reward: ")
	}

	// If there are no stakes to reward, then there's nothing to be done. Exit early here.
	if len(snapshotStakesToReward) == 0 {
		return nil
	}

	// Compute the total stake amount of all snapshot stakes, so we can determine the proportion of each
	// staker's staked amount to the total.
	snapshotStakesTotalStakeAmount := uint256.NewInt()
	for _, snapshotStakeEntry := range snapshotStakesToReward {
		snapshotStakesTotalStakeAmount.Add(snapshotStakesTotalStakeAmount, snapshotStakeEntry.StakeAmountNanos)
	}

	// Check if the sum of all of the stakes is zero. In practice this should never happen because it's not
	// possible for a staker to stake zero DESO. We check it here to make this code more resilient, in case
	// that assumption ever changes elsewhere in the codebase.
	if snapshotStakesTotalStakeAmount.IsZero() {
		return nil
	}

	// Loop through all of the snapshot stakes and reward them.
	for _, snapshotStakeEntry := range snapshotStakesToReward {
		rewardAmount := _computeStakingRewardAmount(
			snapshotStakeEntry.StakeAmountNanos,
			snapshotStakesTotalStakeAmount,
			totalStakingRewards,
		)
		if rewardAmount.IsZero() {
			continue
		}

		// At this point, we know that the staker has non-zero rewards. We need to determine how to
		// distribute the rewards to them. We need to fetch their latest StakeEntry to determine
		// whether they want to restake their rewards or not.

		// Fetch the staker's latest StakeEntry.
		stakeEntry, err := bav.GetStakeEntry(snapshotStakeEntry.ValidatorPKID, snapshotStakeEntry.StakerPKID)
		if err != nil {
			return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem fetching staker's StakeEntry: ")
		}

		// At this point, there are three possible cases:
		// 1. The staker still exists and wants to restake their rewards.
		// 2. The staker still exists and does not want to restake their rewards.
		// 3. The staker has unstaked since the snapshot was taken. They no longer have a
		// StakeEntry. Their stake is currently in lockup.

		// For case 1, we distribute the rewards by adding them to the staker's staked amount.
		if stakeEntry != nil && stakeEntry.RewardMethod == StakeRewardMethodRestake {
			stakeEntry.StakeAmountNanos.Add(stakeEntry.StakeAmountNanos, rewardAmount)
			bav._setStakeEntryMappings(stakeEntry)

			continue
		}

		// For cases 2 and 3, the staker no longer wants their rewards restaked. The staker is still
		// eligible to receive rewards because the validator they had staked to was part of the validator
		// set for the snapshot epoch. Their stake at the time was used to secure the network.

		stakerPublicKey := bav.GetPublicKeyForPKID(snapshotStakeEntry.StakerPKID)
		if _, err = bav._addBalance(rewardAmount.Uint64(), stakerPublicKey); err != nil {
			return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem adding rewards to staker's DESO balance: ")
		}
	}

	return nil
}

// This function is a placeholder that rewards a constant 10 DESO in staking rewards per epoch.
// The staking rewards will be a function of the burn maximizing fee, which has not been
// implemented yet.
//
// TODO: Replace this function once BMF and staking rewards math are complete.
func (bav *UtxoView) _placeholderGetStakingRewardsPerEpoch() *uint256.Int {
	return uint256.NewInt().SetUint64(1e10)
}

// _computeRewardAmount uses integer math to compute the reward amount for each staker rounded down to
// the nearest DESO nano.
func _computeStakingRewardAmount(
	stakeAmount *uint256.Int,
	totalStakeAmount *uint256.Int,
	totalStakingRewards *uint256.Int,
) *uint256.Int {
	output := uint256.NewInt()
	output.Mul(stakeAmount, totalStakingRewards)
	return output.Div(output, totalStakeAmount)
}
