package lib

import (
	"math/big"

	"github.com/deso-protocol/uint256"
	"github.com/pkg/errors"
)

func (bav *UtxoView) DistributeStakingRewardsToSnapshotStakes(blockHeight uint64, blockTimestampNanoSecs int64) ([]*UtxoOperation, error) {
	// Check if we have switched from PoW to PoS yet. If we have not, then the PoS consensus
	// has not started yet. We don't want to distribute any staking rewards until the PoS consensus begins.
	if blockHeight < uint64(bav.Params.ForkHeights.ProofOfStake2ConsensusCutoverBlockHeight) {
		return nil, nil
	}

	// Retrieve the current EpochEntry.
	currentEpochEntry, err := bav.GetCurrentEpochEntry()
	if err != nil {
		return nil, errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem retrieving current EpochEntry: ")
	}

	// Check if the current epoch's timestamp is somehow greater than the block timestamp. This should never happen as long
	// as timestamps are moving forward when connecting each block.
	if currentEpochEntry.CreatedAtBlockTimestampNanoSecs >= blockTimestampNanoSecs {
		return nil, errors.Wrapf(RuleErrorBlockTimestampBeforeEpochStartTimestamp, "DistributeStakingRewardsToSnapshotStakes: ")
	}

	// Compute the amount of time that has elapsed since the current epoch started. As long as the elapsed time is > 0,
	// the fraction of the year will be > 0 as well.
	elapsedTimeNanoSecs := blockTimestampNanoSecs - currentEpochEntry.CreatedAtBlockTimestampNanoSecs
	elapsedFractionOfYear := computeFractionOfYearAsFloat(elapsedTimeNanoSecs)

	// Fetch the staking rewards APY. It is safe to use the APY from the current global params because the staking
	// distribution made here do not affect the PoS consensus until they are snapshotted.
	apyBasisPoints := bav.GetCurrentGlobalParamsEntry().StakingRewardsAPYBasisPoints
	if apyBasisPoints == 0 {
		// If the APY is zero or not yet defined, then there are no staking rewards to distribute.
		return nil, nil
	}

	// Convert the APY from a scaled integer to a float. During the conversion, the interest rate
	// is scaled down. Examples:
	// - a APY basis points value of 526 is converted to a float of 0.0526
	// As long as the scaled interest rate is > 0, the converted float is guaranteed to be non-zero as well.
	apy := convertAPYBasisPointsToFloat(apyBasisPoints)

	// Compute the growth multiplier for the staking rewards. The growth multiplier is computed as:
	// e ^ (apy * elapsedTime / 1 year)
	growthMultiplier := computeGrowthMultiplier(apy, elapsedFractionOfYear)

	// We reward all snapshotted stakes from the current snapshot validator set. This is an O(n) operation
	// that loops through all of the snapshotted stakes and rewards them one by one.
	snapshotStakesToReward, err := bav.GetAllSnapshotStakesToReward()
	if err != nil {
		return nil, errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem retrieving snapshot stakes to reward: ")
	}

	// If there are no stakes to reward, then there's nothing to be done. Exit early here.
	if len(snapshotStakesToReward) == 0 {
		return nil, nil
	}

	// Loop through all of the snapshot stakes; distribute staking rewards to the staker and commissions to
	// their validator.
	var utxoOperations []*UtxoOperation
	for _, snapshotStakeEntry := range snapshotStakesToReward {
		if snapshotStakeEntry == nil {
			// This should never happen. If we encounter a nil entry, then the setter for UtxoView.SnapshotStakesToReward
			// is unexpectedly setting nil values. We just skip such values here.
			continue
		}

		// Compute the staker's portion of the staking reward, and the validator's commission.
		stakerRewardNanos, validatorCommissionNanos, err := bav.computeStakerRewardAndValidatorCommission(
			snapshotStakeEntry, growthMultiplier,
		)
		if err != nil {
			return nil, errors.Wrapf(
				err,
				"DistributeStakingRewardsToSnapshotStakes: problem computing staker reward and validator commission: ",
			)
		}

		// If both the staker reward and the validator commission are zero, then there's nothing to be done.
		// Move on to the next staker.
		if stakerRewardNanos == 0 && validatorCommissionNanos == 0 {
			continue
		}

		// Reward the staker their portion of the staking reward.
		if stakerRewardNanos > 0 {
			var utxoOperation *UtxoOperation
			if utxoOperation, err = bav.distributeStakingReward(
				snapshotStakeEntry.ValidatorPKID, snapshotStakeEntry.StakerPKID, stakerRewardNanos, false,
			); err != nil {
				return nil, errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem distributing staker reward: ")
			}
			utxoOperations = append(utxoOperations, utxoOperation)
		}

		// Reward the validator their commission from the staking reward.
		if validatorCommissionNanos > 0 {
			var utxoOperation *UtxoOperation
			if utxoOperation, err = bav.distributeValidatorCommission(
				snapshotStakeEntry.ValidatorPKID, validatorCommissionNanos); err != nil {
				return nil, errors.Wrapf(err, "DistributeStakingRewardsToSnapshotStakes: problem distributing validator commission reward: ")
			}
			utxoOperations = append(utxoOperations, utxoOperation)
		}
	}

	return utxoOperations, nil
}

func (bav *UtxoView) computeStakerRewardAndValidatorCommission(
	snapshotStakeEntry *StakeEntry,
	growthMultiplier *big.Float,
) (
	_stakerRewardNanos uint64,
	_validatorCommissionNanos uint64,
	_err error,
) {
	// Compute the staker's reward amount using a big float math, and immediately convert it to big int
	// so we can do the remainder of the math using integer operations. This is the only operation where
	// we need float math.
	stakerRewardNanos := convertBigFloatToBigInt(
		computeStakingReward(snapshotStakeEntry.StakeAmountNanos, growthMultiplier),
	)

	// If the reward is 0, then there's nothing to be done. In practice, the reward should never be < 0
	// either, but we check for it here in case it resulted from a rounding error. Either way, we're
	// safe to exit early here.
	if stakerRewardNanos == nil || stakerRewardNanos.Sign() <= 0 {
		return 0, 0, nil
	}

	// At this point, we know that the staker has non-zero rewards. We need to determine how to
	// distribute the rewards to them, and how to distribute the validator's commissions.

	// Compute the validator's commission and deduct it from the staker's reward.
	validatorCommissionNanos := big.NewInt(0)

	// We only compute validator commission if the staker had delegated stake to another validator. If the staker
	// staked to themselves, then there's no reason to compute the validator commission.
	if !snapshotStakeEntry.StakerPKID.Eq(snapshotStakeEntry.ValidatorPKID) {
		// Fetch the ValidatorEntry that the stake is delegated to. The validator is guaranteed to be in the
		// snapshot validator set, because only stakes from the snapshot validator set are eligible to receive
		// rewards.
		validatorEntry, err := bav.GetCurrentSnapshotValidatorSetEntryByPKID(snapshotStakeEntry.ValidatorPKID)
		if err != nil {
			return 0, 0, errors.Wrapf(err, "computeStakerRewardAndValidatorCommission: problem fetching validator entry: ")
		}
		if validatorEntry == nil || validatorEntry.isDeleted {
			// This should never happen. If we can't find the validator, then something is wrong. It's safest to error
			// and return early here.
			return 0, 0, errors.Errorf("computeStakerRewardAndValidatorCommission: validator entry should never be nil")
		}

		if validatorEntry.DelegatedStakeCommissionBasisPoints > 0 {
			// We use integer math to compute the validator's commission. The commission is computed as:
			// floor(stakerReward * validatorCommissionBasisPoints / 10000)
			validatorCommissionNanos = computeValidatorCommission(
				stakerRewardNanos, validatorEntry.DelegatedStakeCommissionBasisPoints,
			)

			if validatorCommissionNanos.Cmp(stakerRewardNanos) > 0 {
				// This should never happen. If the validator's commission is greater than the total staker reward amount,
				// then something has gone wrong.
				return 0, 0, errors.Errorf(
					"computeStakerRewardAndValidatorCommission: validator commission is greater than staker reward amount",
				)
			}

			// Deduct the validator commission from the staker's reward.
			stakerRewardNanos = big.NewInt(0).Sub(stakerRewardNanos, validatorCommissionNanos)
		}
	}

	// At this point, we have the staker's reward and the validator's commission. We need to convert them
	// to uint64s and return them.
	if !stakerRewardNanos.IsUint64() || !validatorCommissionNanos.IsUint64() {
		return 0, 0, errors.Errorf(
			"computeStakerRewardAndValidatorCommission: staker reward or validator commission is not a uint64",
		)
	}

	return stakerRewardNanos.Uint64(), validatorCommissionNanos.Uint64(), nil
}

func (bav *UtxoView) distributeStakingReward(
	validatorPKID *PKID,
	stakerPKID *PKID,
	rewardNanos uint64,
	isValidatorCommission bool,
) (*UtxoOperation, error) {
	// Fetch the staker's latest StakeEntry.
	stakeEntry, err := bav.GetStakeEntry(validatorPKID, stakerPKID)
	if err != nil {
		return nil, errors.Wrapf(err, "distributeStakingReward: problem fetching staker's StakeEntry: ")
	}

	// At this point, there are three possible cases:
	// 1. The stake entry still exists and wants to restake their rewards.
	// 2. The stake entry still exists and does not want to restake their rewards.
	// 3. The stake entry has unstaked since the snapshot was taken.

	var utxoOperation *UtxoOperation
	// For case 1, we distribute the rewards by adding them to the staker's staked amount.
	if stakeEntry != nil && stakeEntry.RewardMethod == StakingRewardMethodRestake {
		validatorEntry, err := bav.GetValidatorByPKID(stakeEntry.ValidatorPKID)
		if err != nil {
			return nil, errors.Wrapf(err, "distributeStakingReward: problem fetching validator entry: ")
		}
		utxoOperation = &UtxoOperation{
			Type:                 OperationTypeStakeDistributionRestake,
			PrevStakeEntries:     []*StakeEntry{stakeEntry.Copy()},
			PrevValidatorEntry:   validatorEntry.Copy(),
			StakeAmountNanosDiff: rewardNanos,
			StateChangeMetadata: &StakeRewardStateChangeMetadata{
				ValidatorPKID:         validatorPKID,
				StakerPKID:            stakerPKID,
				RewardNanos:           rewardNanos,
				StakingRewardMethod:   StakingRewardMethodRestake,
				IsValidatorCommission: isValidatorCommission,
			},
		}
		stakeEntry.StakeAmountNanos = uint256.NewInt(0).Add(stakeEntry.StakeAmountNanos, uint256.NewInt(rewardNanos))
		bav._setStakeEntryMappings(stakeEntry)
		validatorEntry.TotalStakeAmountNanos = uint256.NewInt(0).Add(validatorEntry.TotalStakeAmountNanos, uint256.NewInt(rewardNanos))
		bav._setValidatorEntryMappings(validatorEntry)
		return utxoOperation, nil
	}

	// For cases 2 and 3, the staker does not want their rewards restaked. The staker is still
	// eligible to receive rewards because their stake was used to secure the network. So we pay out
	// the rewards directly to the staker's wallet.

	stakerPublicKey := bav.GetPublicKeyForPKID(stakerPKID)
	if utxoOperation, err = bav._addBalanceForStakeReward(rewardNanos, stakerPublicKey); err != nil {
		return nil, errors.Wrapf(err, "distributeStakingReward: problem adding rewards to staker's DESO balance: ")
	}
	utxoOperation.StateChangeMetadata = &StakeRewardStateChangeMetadata{
		ValidatorPKID:         validatorPKID,
		StakerPKID:            stakerPKID,
		RewardNanos:           rewardNanos,
		StakingRewardMethod:   StakingRewardMethodPayToBalance,
		IsValidatorCommission: isValidatorCommission,
	}

	return utxoOperation, nil
}

func (bav *UtxoView) distributeValidatorCommission(validatorPKID *PKID, commissionNanos uint64) (*UtxoOperation, error) {
	// Here, we treat the validator's commission identically to staking rewards. We view commissions as another source of staking
	// rewards that validators receive at the end of each epoch. And these commissions are eligible to be restaked if the validator
	// desires. To determine whether to re-stake commissions or pay out the commissions to the validator's wallet, we rely on the
	// validators own StakeEntry where they have staked to themselves, and the RewardMethod flag on the entry. The logic works as follows:
	// - If the validator has staked to themselves, and they have reward restaking enabled, then their commissions are restaked.
	// - If the validator has not staked to themselves, or they have reward restaking disabled, then their commissions are paid out
	//   to their wallet.
	//
	// This approach has a few advantages:
	// 1. It gives validators an easy opt-in feature to restake their commissions. This is useful for validators that want to maximize
	// their staking rewards over the long run. Validators can opt out of it by disabling reward restaking on their own StakeEntry.
	// 2. It simplifies the validator commission distribution code by re-using the same code path for distributing staking
	// rewards. By requiring the validator to already have a StakeEntry for themselves if they want to restake their commissions,
	// this approach allows us to avoid manually creating new StakeEntries for the validator specifically for restaking commissions.
	//
	// TODO: The downside of the above is that it couples the restaking behavior for validator commissions and the validator's own
	// staking reward. This is fine though, because if the validator wants to restake their own rewards but not their commissions, then
	// they can stake to themselves using a separate wallet and only enable reward restaking for that StakeEntry.
	//
	// If the above isn't desired the behavior, then we can alternatively always pay out validator's commission directly to their wallet.
	return bav.distributeStakingReward(validatorPKID, validatorPKID, commissionNanos, true)
}

var (
	_basisPointsAsInt       = big.NewInt(int64(MaxBasisPoints))
	_basisPointsAsFloat     = NewFloat().SetUint64(MaxBasisPoints)
	_nanoSecsPerYearAsFloat = NewFloat().SetUint64(NanoSecsPerYear)
)

func convertBigFloatToBigInt(float *big.Float) *big.Int {
	floatAsInt, _ := float.Int(nil)
	return floatAsInt
}

func convertAPYBasisPointsToFloat(apyBasisPoints uint64) *big.Float {
	apyBasisPointsAsFloat := NewFloat().SetUint64(apyBasisPoints)
	return NewFloat().Quo(apyBasisPointsAsFloat, _basisPointsAsFloat)
}

func computeFractionOfYearAsFloat(nanoSecs int64) *big.Float {
	nanoSecsAsFloat := NewFloat().SetInt64(nanoSecs)
	return NewFloat().Quo(nanoSecsAsFloat, _nanoSecsPerYearAsFloat)
}

func computeGrowthMultiplier(apy *big.Float, elapsedTimeFractionOfYear *big.Float) *big.Float {
	growthExponent := NewFloat().Mul(apy, elapsedTimeFractionOfYear) // apy * elapsedTime / 1 year
	return BigFloatExp(growthExponent)                               // e ^ (apy * elapsedTime / 1 year)
}

// computeStakingReward uses float math to compute the compound interest on the stake amounts based on the
// elapsed time since the last staking reward distribution and the APY. The growthMultiplier is computed as:
// e ^ (apy * elapsedTime / 1 year)
//
// It produces the result for: stakeAmount * [e ^ (apy * elapsedTime / 1 year) - 1]
func computeStakingReward(stakeAmountNanos *uint256.Int, growthMultiplier *big.Float) *big.Float {
	stakeAmountFloat := NewFloat().SetInt(stakeAmountNanos.ToBig())
	finalStakeAmountNanos := NewFloat().Mul(stakeAmountFloat, growthMultiplier)  // stakeAmount * [e ^ (apy * elapsedTime / 1 year)]
	rewardAmountNanos := NewFloat().Sub(finalStakeAmountNanos, stakeAmountFloat) // stakeAmount * [e ^ (apy * elapsedTime / 1 year) - 1]
	if rewardAmountNanos.Sign() < 0 {
		return NewFloat() // This should not be possible, but we clamp the result to zero just in case.
	}
	return rewardAmountNanos
}

// computeValidatorCommission uses integer math to compute the validator's commission amount based on the staker's
// reward amount and the validator's commission rate. Wherever possible, we rely on integer math so that rounding
// errors are simpler to reason through.
//
// It produces the integer result for: floor[(stakerReward * validatorCommissionBasisPoints) / 1e4]
func computeValidatorCommission(stakerRewardNanos *big.Int, validatorCommissionBasisPoints uint64) *big.Int {
	scaledStakerReward := big.NewInt(0).Mul(stakerRewardNanos, big.NewInt(int64(validatorCommissionBasisPoints)))
	return big.NewInt(0).Div(scaledStakerReward, _basisPointsAsInt)
}
