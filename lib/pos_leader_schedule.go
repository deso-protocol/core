package lib

import (
	"github.com/holiman/uint256"
	"github.com/pkg/errors"
	"math/big"
	"math/rand"
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
		return nil, nil
	}

	// Sum TotalStakeAmountNanos.
	totalStakeAmountNanos := uint256.NewInt()
	for _, validatorEntry := range validatorEntries {
		totalStakeAmountNanos, err = SafeUint256().Add(totalStakeAmountNanos, validatorEntry.TotalStakeAmountNanos)
		if err != nil {
			return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error summing TotalStakeAmountNanos: ")
		}
	}

	var leaderSchedule []*ValidatorEntry

	r := rand.New(rand.NewSource(int64(currentRandomSeedHash.ToUint64())))

	// In a loop...

	for _, validatorEntry := range validatorEntries {
		// Pick a random uin256.Int between 0 and TotalStakeAmountNanos.
		randomUint256, err := RandomUint256(r)
		if err != nil {
			return nil, errors.Wrapf(err, "UtxoView.GenerateLeaderSchedule: error generating random uint256: ")
		}

		// Iterate through ValidatorEntries until ValidatorEntry.TotalStakeAmountNanos >= randomIter.
		if validatorEntry.TotalStakeAmountNanos.Gt(randomUint256) {
			leaderSchedule = append(leaderSchedule, validatorEntry)
		}

		// Add that ValidatorEntry to the leaderSchedule. Remove that ValidatorEntry from the validatorEntries slice.
		// Subtract the ValidatorEntry.TotalStakeAmountNanos from the TotalStakeAmountNanos.
	}

	return leaderSchedule, nil
}

func RandomUint256(r *rand.Rand) (*uint256.Int, error) {
	digits := []byte("0123456789abcdef")
	uint256ByteSlice := make([]byte, 256)
	for i := 0; i < 256; i++ {
		uint256ByteSlice[i] = digits[r.Intn(16)]
	}
	uint256String := string(uint256ByteSlice)

	uint256BigInt, success := big.NewInt(0).SetString(uint256String, 16)
	if !success {
		return nil, errors.New("RandomUint256: problem converting string to big.Int")
	}
	randUint256 := uint256.NewInt()
	randUint256.SetFromBig(uint256BigInt)
	return randUint256, nil
}
