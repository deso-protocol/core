package lib

import (
	"math/big"

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

	// Fetch the per-epoch interest rate for staking rewards.
	interestRateScaled := snapshotGlobalParamsEntry.StakingRewardInterestRatePerEpochScaled1e9
	if interestRateScaled == 0 {
		// If the interest rate is zero or not yet defined, then there are no staking rewards to distribute.
		return nil
	}

	// Convert the interest rate from a scaled integer to a float. During the conversion, the interest rate
	// is scaled down. Examples:
	// - a scaled interest rate of 0.1 * 1e9 is converted to a float of 0.1
	// - a scaled interest rate of 0.01 * 1e9 is converted to a float of 0.01
	// As long as the scaled interest rate is > 0, the converted float is guaranteed to be non-zero as well.
	interestRateAsFloat := convertScaledInterestRateToFloat(interestRateScaled)

	// We reward all snapshotted stakes from the current snapshot validator set. This is an O(n) operation
	// that loops through all of the snapshotted stakes and rewards them one by one.
	snapshotStakesToReward, err := bav.GetSnapshotStakesToRewardByStakeAmount(snapshotGlobalParamsEntry.StakingRewardsMaxNumStakes)
	if err != nil {
		return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem retrieving snapshot stakes to reward: ")
	}

	// If there are no stakes to reward, then there's nothing to be done. Exit early here.
	if len(snapshotStakesToReward) == 0 {
		return nil
	}

	// Loop through all of the snapshot stakes; distribute staking rewards to the staker and commissions to
	// their validator.
	for _, snapshotStakeEntry := range snapshotStakesToReward {

		// Compute the staker's portion of the staking reward, and the validator's commission.
		stakerReward, validatorCommission, err := bav.computeStakerRewardAndValidatorCommission(snapshotStakeEntry, interestRateAsFloat)
		if err != nil {
			return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem computing staker reward and validator commission: ")
		}

		// If either the staker reward or the validator commission is zero, then there's nothing to be done. Move on to the next staker.
		if stakerReward == 0 || validatorCommission == 0 {
			continue
		}

		// Reward the staker their portion of the staking reward.
		if stakerReward > 0 {
			if err = bav.distributeStakingReward(snapshotStakeEntry.ValidatorPKID, snapshotStakeEntry.StakerPKID, stakerReward); err != nil {
				return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem distributing staker reward: ")
			}
		}

		// Reward the validator their commission from the staking reward.
		if validatorCommission > 0 {
			if err = bav.distributeValidatorCommission(snapshotStakeEntry.ValidatorPKID, validatorCommission); err != nil {
				return errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem distributing validator commission reward: ")
			}
		}
	}

	return nil
}

func (bav *UtxoView) computeStakerRewardAndValidatorCommission(
	snapshotStakeEntry *SnapshotStakeEntry,
	interestRateAsFloat *big.Float,
) (
	_stakerReward uint64,
	_validatorCommission uint64,
	_err error,
) {
	// Compute the staker's reward amount using a big float math, and immediately convert it to big int
	// so we can do the remainder of the math using integer operations. This is the only operation where
	// we need float math.
	stakerReward := convertBigFloatToBigInt(
		computeStakingReward(snapshotStakeEntry.StakeAmountNanos, interestRateAsFloat),
	)

	// If the reward is 0, then there's nothing to be done. In practice, the reward should never be < 0
	// either, but we check for it here in case it resulted from a rounding error. Either way, we're
	// safe to exit early here.
	if stakerReward.Sign() <= 0 {
		return 0, 0, nil
	}

	// At this point, we know that the staker has non-zero rewards. We need to determine how to
	// distribute the rewards to them, and how to distribute the validator's commissions.

	// Compute the validator's commission and deduct it from the staker's reward.
	validatorCommission := big.NewInt(0)

	// We only compute validator commission if the staker had delegated stake to another validator. If the staker
	// staked to themselves, then there's no reason to compute the validator commission.
	if !snapshotStakeEntry.StakerPKID.Eq(snapshotStakeEntry.ValidatorPKID) {
		// Fetch the ValidatorEntry that the stake is delegated to. The validator is guaranteed to be in the
		// snapshot validator set, because only stakes from the snapshot validator set are eligible to receive
		// rewards.
		validatorEntry, err := bav.GetSnapshotValidatorSetEntryByPKID(snapshotStakeEntry.ValidatorPKID)
		if err != nil {
			return 0, 0, errors.Wrapf(err, "computeStakerRewardAndValidatorCommission: problem fetching validator entry: ")
		}
		if validatorEntry == nil {
			// This should never happen. If we can't find the validator, then something is wrong. It's safest to error
			// and return early here.
			return 0, 0, errors.Errorf("computeStakerRewardAndValidatorCommission: validator entry should never be nil")
		}

		if validatorEntry.DelegatedStakeCommissionBasisPoints > 0 {
			// We use integer math to compute the validator's commission. The commission is computed as:
			// floor(stakerReward * validatorCommissionBasisPoints / 10000)
			validatorCommission = computeValidatorCommission(stakerReward, validatorEntry.DelegatedStakeCommissionBasisPoints)

			if validatorCommission.Cmp(stakerReward) > 0 {
				// This should never happen. If the validator's commission is greater than the total staker reward amount,
				// then something has gone wrong.
				return 0, 0, errors.Errorf("computeStakerRewardAndValidatorCommission: validator commission is greater than staker reward amount")
			}

			// Subtract out the validator commission from the staker's reward.
			stakerReward.Sub(stakerReward, validatorCommission)
		}
	}

	// At this point, we have the staker's reward and the validator's commission. We need to convert them
	// to uint64s and return them.
	if !stakerReward.IsUint64() || !validatorCommission.IsUint64() {
		return 0, 0, errors.Errorf("computeStakerRewardAndValidatorCommission: staker reward or validator commission is not a uint64")
	}

	return stakerReward.Uint64(), validatorCommission.Uint64(), nil
}

func (bav *UtxoView) distributeStakingReward(validatorPKID *PKID, stakerPKID *PKID, rewardAmount uint64) error {
	// Fetch the staker's latest StakeEntry.
	stakeEntry, err := bav.GetStakeEntry(validatorPKID, stakerPKID)
	if err != nil {
		return errors.Wrapf(err, "distributeStakingReward: problem fetching staker's StakeEntry: ")
	}

	// At this point, there are three possible cases:
	// 1. The stake entry still exists and wants to restake their rewards.
	// 2. The stake entry still exists and does not want to restake their rewards.
	// 3. The stake entry has unstaked since the snapshot was taken.

	// For case 1, we distribute the rewards by adding them to the staker's staked amount.
	if stakeEntry != nil && stakeEntry.RewardMethod == StakingRewardMethodRestake {
		stakeEntry.StakeAmountNanos.Add(stakeEntry.StakeAmountNanos, uint256.NewInt().SetUint64(rewardAmount))
		bav._setStakeEntryMappings(stakeEntry)

		return nil
	}

	// For cases 2 and 3, the staker no longer wants their rewards restaked. The staker is still
	// eligible to receive rewards because their stake was used to secure the network. So we pay out
	// the rewards directly to the staker's wallet.

	stakerPublicKey := bav.GetPublicKeyForPKID(stakerPKID)
	if _, err = bav._addBalance(rewardAmount, stakerPublicKey); err != nil {
		return errors.Wrapf(err, "distributeStakingReward: problem adding rewards to staker's DESO balance: ")
	}

	return nil
}

func (bav *UtxoView) distributeValidatorCommission(validatorPKID *PKID, commissionAmount uint64) error {
	// Here we treat the validator's commission identically to staking rewards. We view commissions as another source of staking rewards
	// that validators have received by staking to themselves. This has a few advantages:
	// 1. It gives validators an opt-in feature to restake their commissions. This is useful for validators that want to maximize their
	// staking rewards over the long run. Validators can opt out of it by disabling reward restaking on their own StakeEntry.
	// 2. It simplifies the validator commission distribution code path by re-using the same code path for distributing staking
	// rewards when the validator has staked to themselves.
	//
	// TODO: The downside of the above is that it couples the restaking behavior for validator commissions and the validator's own
	// staking reward. This seems fine though, as it is unlikely that a validator will want to restake only a subtset of their rewards.
	// If the above isn't desired the behavior, then we can alternatively pay out validator's commission directly to their wallet.
	return bav.distributeStakingReward(validatorPKID, validatorPKID, commissionAmount)
}

const (
	_basisPointsScalingFactor               = uint64(10000)      // 1e4
	_stakingRewardInterestRateScalingFactor = uint64(1000000000) // 1e9
)

var (
	_basisPointsScalingFactorAsInt                 = big.NewInt(int64(_basisPointsScalingFactor))
	_stakingRewardInterestRateScalingFactorAsFloat = NewFloat().SetUint64(_stakingRewardInterestRateScalingFactor)
)

func convertBigFloatToBigInt(float *big.Float) *big.Int {
	floatAsInt, _ := float.Int(nil)
	return floatAsInt
}

func convertScaledInterestRateToFloat(scaledInterestRate uint64) *big.Float {
	scaledInterestRateFloat := NewFloat().SetUint64(scaledInterestRate)
	return scaledInterestRateFloat.Quo(scaledInterestRateFloat, _stakingRewardInterestRateScalingFactorAsFloat)
}

func computeStakingReward(stakeAmount *uint256.Int, interestRate *big.Float) *big.Float {
	stakeAmountFloat := NewFloat().SetInt(stakeAmount.ToBig())
	return BigFloatPow(stakeAmountFloat, interestRate)
}

func computeValidatorCommission(stakerReward *big.Int, validatorCommissionBasisPoints uint64) *big.Int {
	scaledStakerReward := big.NewInt(0).Mul(stakerReward, big.NewInt(int64(validatorCommissionBasisPoints)))
	return scaledStakerReward.Div(scaledStakerReward, _basisPointsScalingFactorAsInt)
}
