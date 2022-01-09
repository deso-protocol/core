package lib

// supply.go defines all of the logic regarding the DeSo supply schedule. It also
// defines the Bitcoin <-> DeSo exchange schedule.

type MiningSupplyIntervalStart struct {
	StartBlockHeight uint32
	BlockRewardNanos uint64
}

type PurchaseSupplyIntervalStart struct {
	// How much each unit costs to purchase in Satoshis.
	SatoshisPerUnit uint64
	// The total supply cutoff at which this price applies.
	SupplyStartNanos uint64
}

const (
	NanosPerUnit  = uint64(1000000000)
	BlocksPerYear = uint32(12 * 24 * 365)
	BlocksPerDay  = uint32(12 * 24)
	// Every 1M DeSo we sell causes the price to increase by a factor of 2.
	TrancheSizeNanos = uint64(1000000000000000)
	// When exchanging Bitcoin for DeSo, we don't allow transactions to create
	// less than this amount. This avoids issues around small transactions that
	// exploit floating point errors.
	MinNanosToCreate = 50

	// The price of DeSo at the beginning.
	StartDeSoPriceUSDCents = 50
	SatoshisPerBitcoin     = 100000000

	// The minimum and maximum Bitcoin prices, used as a sanity-check.
	MinUSDCentsPerBitcoin = 100 * 100
	MaxUSDCentsPerBitcoin = 1000000 * 100

	// Used for sanity checks for now. This is not necessarily the actual the max supply.
	MaxNanos = uint64(30000000) * NanosPerUnit
)

var (
	NaturalLogOfTwo = BigFloatLog(NewFloat().SetUint64(2))

	DeflationBombBlockRewardAdjustmentBlockHeight = uint32(32060)

	MiningSupplyIntervals = []*MiningSupplyIntervalStart{
		{
			StartBlockHeight: 0,
			BlockRewardNanos: 1 * NanosPerUnit,
		},
		// Adjust the block reward as part of the deflation bomb to mark the DeSo
		// dev community's commitment to a zero-waste, environmentally-friendly
		// consensus mechanism. Do a smooth ramp in order to minimize issues with
		// block mining times.
		{
			StartBlockHeight: DeflationBombBlockRewardAdjustmentBlockHeight,
			BlockRewardNanos: NanosPerUnit * 3 / 4,
		},
		{
			StartBlockHeight: DeflationBombBlockRewardAdjustmentBlockHeight + BlocksPerDay,
			BlockRewardNanos: NanosPerUnit / 2,
		},
		{
			StartBlockHeight: DeflationBombBlockRewardAdjustmentBlockHeight + 2*BlocksPerDay,
			BlockRewardNanos: NanosPerUnit / 4,
		},
		{
			StartBlockHeight: DeflationBombBlockRewardAdjustmentBlockHeight + 3*BlocksPerDay,
			BlockRewardNanos: NanosPerUnit / 8,
		},
		{
			StartBlockHeight: DeflationBombBlockRewardAdjustmentBlockHeight + 4*BlocksPerDay,
			BlockRewardNanos: NanosPerUnit / 10,
		},
		// Leave the block reward at .1 for the medium-term then tamp it down to zero.
		// Note that the consensus mechanism will likely change to something more
		// more energy-efficient before this point.
		{
			StartBlockHeight: 15 * BlocksPerYear,
			BlockRewardNanos: NanosPerUnit / 20,
		},
		{
			StartBlockHeight: 32 * BlocksPerYear,
			BlockRewardNanos: 0,
		},
	}

	// This is used for various calculations but can be updated on the fly with a
	// special transaction type in the event that the Bitcoin price fluctuates
	// significantly. We make this a var rather than a const so that tests can
	// change the value.
	InitialUSDCentsPerBitcoinExchangeRate = uint64(3000000)
)

// CalcBlockRewardNanos computes the block reward for a given block height.
func CalcBlockRewardNanos(blockHeight uint32) uint64 {
	if blockHeight == 0 {
		return MiningSupplyIntervals[0].BlockRewardNanos
	}

	// Skip the first interval since we know we're past block height zero.
	for intervalIndex, intervalStart := range MiningSupplyIntervals {
		if intervalIndex == 0 {
			// Skip the first iteration.
			continue
		}
		if intervalStart.StartBlockHeight > blockHeight {
			// We found an interval that has a greater block height than what was
			// passed in, so the interval just before it should be the one containing
			// this block height.
			return MiningSupplyIntervals[intervalIndex-1].BlockRewardNanos
		}
	}

	// If we get here then all of the intervals had a lower block height than
	// the passed-in block height. In this case, the block reward is zero.
	return 0
}

func GetStartPriceSatoshisPerDeSo(usdCentsPerBitcoinExchangeRate uint64) uint64 {
	return StartDeSoPriceUSDCents * SatoshisPerBitcoin / usdCentsPerBitcoinExchangeRate
}

func GetSatoshisPerUnitExchangeRate(startNanos uint64, usdCentsPerBitcoinExchangeRate uint64) uint64 {
	startPriceSatoshisPerDeSo := GetStartPriceSatoshisPerDeSo(usdCentsPerBitcoinExchangeRate)
	val, _ := Mul(NewFloat().SetUint64(startPriceSatoshisPerDeSo), BigFloatPow(
		bigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos)))).Uint64()
	return val
}

func CalcNanosToCreate(
	startNanos uint64, satoshisToBurn uint64, usdCentsPerBitcoinExchangeRate uint64) (
	_nanosToCreate uint64) {

	// Given the amount this user wants to burn, we have a formula that tells us
	// how much DeSo we should have after processing the transaction. The
	// "tranche size nanos" below simply modulates how quickly the price doubles.
	// The smaller it is, the faster the price increases with each DeSo sold.
	//
	// price in satoshis per DeSo
	//   = 2 ^((nanos sold) / tranche size nanos) * SatoshisPerDeSo
	//
	// Taking the integral of this with respect to the nanos sold tells us how
	// many Bitcoin we burn for a given number of nanos.
	//
	// Bitcoin to burn = (SatoshisPerDeSo) * (tranche size in nanos) / (ln(2)) * (
	// 		2^((final DeSo burned) / (tranche size in nanos) -
	//    2^((initial DeSo burned) / (tranche size in nanos)))
	//
	// Solving this equation for "final DeSo burned" yields the formula you see
	// below, which we can then use to figure out how many nanos we should create.
	startPriceSatoshisPerDeSo := GetStartPriceSatoshisPerDeSo(usdCentsPerBitcoinExchangeRate)
	nanosComponent := Div(NewFloat().SetUint64(NanosPerUnit), NewFloat().SetUint64(TrancheSizeNanos))
	bitcoinComponent := Div(NewFloat().SetUint64(satoshisToBurn), NewFloat().SetUint64(startPriceSatoshisPerDeSo))
	bigFloatFinalDeSoNanos := Mul(NewFloat().SetUint64(TrancheSizeNanos), BigFloatLog2(
		Add(Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)),
			BigFloatPow(bigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos))))))

	// If somehow the final amount is less than what we started with then return
	// zero just to be safe.
	finalDeSoNanos, _ := bigFloatFinalDeSoNanos.Uint64()
	if finalDeSoNanos <= startNanos {
		return uint64(0)
	}
	nanosToCreate := finalDeSoNanos - startNanos

	// Return zero unless we're above a threshold amount. This avoids floating
	// point issues around very small exchanges.
	if nanosToCreate <= MinNanosToCreate {
		return uint64(0)
	}

	return nanosToCreate
}
