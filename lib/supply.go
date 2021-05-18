package lib

// supply.go defines all of the logic regarding the BitClout supply schedule. It also
// defines the Bitcoin <-> BitClout exchange schedule.

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
	// Every 1M BitClout we sell causes the price to increase by a factor of 2.
	TrancheSizeNanos = uint64(1000000000000000)
	// When exchanging Bitcoin for BitClout, we don't allow transactions to create
	// less than this amount. This avoids issues around small transactions that
	// exploit floating point errors.
	MinNanosToCreate = 50

	// The price of BitClout at the beginning.
	StartBitCloutPriceUSDCents = 50
	SatoshisPerBitcoin         = 100000000

	// The minimum and maximum Bitcoin prices, used as a sanity-check.
	MinUSDCentsPerBitcoin = 100 * 100
	MaxUSDCentsPerBitcoin = 1000000 * 100

	// Used for sanity checks for now. This is not necessarily the actual the max supply.
	MaxNanos = uint64(30000000) * NanosPerUnit
)

var (
	NaturalLogOfTwo = BigFloatLog(NewFloat().SetUint64(2))

	MiningSupplyIntervals = []*MiningSupplyIntervalStart{
		{
			StartBlockHeight: 0,
			BlockRewardNanos: 1 * NanosPerUnit,
		},
		{
			StartBlockHeight: 1 * BlocksPerYear,
			BlockRewardNanos: 1 * NanosPerUnit / 2,
		},
		{
			StartBlockHeight: 3 * BlocksPerYear,
			BlockRewardNanos: NanosPerUnit / 4,
		},
		{
			StartBlockHeight: 7 * BlocksPerYear,
			BlockRewardNanos: NanosPerUnit / 8,
		},
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

func GetStartPriceSatoshisPerBitClout(usdCentsPerBitcoinExchangeRate uint64) uint64 {
	return StartBitCloutPriceUSDCents * SatoshisPerBitcoin / usdCentsPerBitcoinExchangeRate
}

func GetSatoshisPerUnitExchangeRate(startNanos uint64, usdCentsPerBitcoinExchangeRate uint64) uint64 {
	startPriceSatoshisPerBitClout := GetStartPriceSatoshisPerBitClout(usdCentsPerBitcoinExchangeRate)
	val, _ := Mul(NewFloat().SetUint64(startPriceSatoshisPerBitClout), BigFloatPow(
		bigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos)))).Uint64()
	return val
}

func CalcNanosToCreate(
	startNanos uint64, satoshisToBurn uint64, usdCentsPerBitcoinExchangeRate uint64) (
	_nanosToCreate uint64) {

	// Given the amount this user wants to burn, we have a formula that tells us
	// how much BitClout we should have after processing the transaction. The
	// "tranche size nanos" below simply modulates how quickly the price doubles.
	// The smaller it is, the faster the price increases with each BitClout sold.
	//
	// price in satoshis per BitClout
	//   = 2 ^((nanos sold) / tranche size nanos) * SatoshisPerBitClout
	//
	// Taking the integral of this with respect to the nanos sold tells us how
	// many Bitcoin we burn for a given number of nanos.
	//
	// Bitcoin to burn = (SatoshisPerBitClout) * (tranche size in nanos) / (ln(2)) * (
	// 		2^((final BitClout burned) / (tranche size in nanos) -
	//    2^((initial BitClout burned) / (tranche size in nanos)))
	//
	// Solving this equation for "final BitClout burned" yields the formula you see
	// below, which we can then use to figure out how many nanos we should create.
	startPriceSatoshisPerBitClout := GetStartPriceSatoshisPerBitClout(usdCentsPerBitcoinExchangeRate)
	nanosComponent := Div(NewFloat().SetUint64(NanosPerUnit), NewFloat().SetUint64(TrancheSizeNanos))
	bitcoinComponent := Div(NewFloat().SetUint64(satoshisToBurn), NewFloat().SetUint64(startPriceSatoshisPerBitClout))
	bigFloatFinalBitCloutNanos := Mul(NewFloat().SetUint64(TrancheSizeNanos), BigFloatLog2(
		Add(Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)),
			BigFloatPow(bigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos))))))

	// If somehow the final amount is less than what we started with then return
	// zero just to be safe.
	finalBitCloutNanos, _ := bigFloatFinalBitCloutNanos.Uint64()
	if finalBitCloutNanos <= startNanos {
		return uint64(0)
	}
	nanosToCreate := finalBitCloutNanos - startNanos

	// Return zero unless we're above a threshold amount. This avoids floating
	// point issues around very small exchanges.
	if nanosToCreate <= MinNanosToCreate {
		return uint64(0)
	}

	return nanosToCreate
}
