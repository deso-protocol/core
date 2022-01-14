package lib

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	satoshisPerBitcoin = 100000000
)

func TestTotalMiningSupply(t *testing.T) {
	require := require.New(t)

	// Sum all of the mining intervals to make sure there is no overflow.
	totalMiningSupply := uint64(0)
	for intervalIndex, currentInterval := range MiningSupplyIntervals {
		if intervalIndex == 0 {
			// Skip the first index
			continue
		}
		prevInterval := MiningSupplyIntervals[intervalIndex-1]
		blockRewardNanos := prevInterval.BlockRewardNanos
		numBlocksInInterval := currentInterval.StartBlockHeight - prevInterval.StartBlockHeight

		numNanosMinedInInterval := blockRewardNanos * uint64(numBlocksInInterval)
		totalMiningSupply += numNanosMinedInInterval
	}
	require.Equal(int64(276238800000000), int64(totalMiningSupply))
}

func TestCalcBlockReward(t *testing.T) {
	require := require.New(t)

	blocksPerYear := (time.Hour * 24 * 365 / DeSoMainnetParams.TimeBetweenBlocks)
	require.Equal(int64(blocksPerYear), int64(BlocksPerYear))

	require.Equal(1*NanosPerUnit, CalcBlockRewardNanos(0))
	require.Equal(1*NanosPerUnit, CalcBlockRewardNanos(1))

	// .75
	require.Equal(1*NanosPerUnit, CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight-1))
	require.Equal(int64(float64(NanosPerUnit)*.75), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight)))
	// .5
	require.Equal(int64(float64(NanosPerUnit)*.75), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+288-1)))
	require.Equal(int64(float64(NanosPerUnit)*.5), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+288)))
	// .25
	require.Equal(int64(float64(NanosPerUnit)*.5), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+2*288-1)))
	require.Equal(int64(float64(NanosPerUnit)*.25), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+2*288)))
	// .125
	require.Equal(int64(float64(NanosPerUnit)*.25), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+3*288-1)))
	require.Equal(int64(float64(NanosPerUnit)*.125), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+3*288)))
	// .1
	require.Equal(int64(float64(NanosPerUnit)*.125), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+4*288-1)))
	require.Equal(int64(float64(NanosPerUnit)*.1), int64(CalcBlockRewardNanos(DeflationBombBlockRewardAdjustmentBlockHeight+4*288)))

	// .05
	require.Equal(int64(1*NanosPerUnit/10), int64(CalcBlockRewardNanos(15*BlocksPerYear-1)))
	require.Equal(NanosPerUnit/20, CalcBlockRewardNanos(15*BlocksPerYear))
	require.Equal(NanosPerUnit/20, CalcBlockRewardNanos(15*BlocksPerYear+1))
	// 0
	require.Equal(NanosPerUnit/20, CalcBlockRewardNanos(32*BlocksPerYear-1))
	require.Equal(uint64(0), CalcBlockRewardNanos(32*BlocksPerYear))
	require.Equal(uint64(0), CalcBlockRewardNanos(32*BlocksPerYear+1))
	require.Equal(uint64(0), CalcBlockRewardNanos(35*BlocksPerYear+1))
	require.Equal(uint64(0), CalcBlockRewardNanos(math.MaxUint32))
}

func TestGetPrice(t *testing.T) {
	oldInitialUSDCentsPerBitcoinExchangeRate := InitialUSDCentsPerBitcoinExchangeRate
	InitialUSDCentsPerBitcoinExchangeRate = 1350000
	defer func() {
		InitialUSDCentsPerBitcoinExchangeRate = oldInitialUSDCentsPerBitcoinExchangeRate
	}()
	assert := assert.New(t)
	{
		startPriceSatoshis := GetStartPriceSatoshisPerDeSo(InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(0, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(10, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1000, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1000000000, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(10000000000, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(100000000000, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis+2), int64(GetSatoshisPerUnitExchangeRate(1000*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(2*startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1000000*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(16135), int64(GetSatoshisPerUnitExchangeRate(2123456*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(8*startPriceSatoshis-1), int64(GetSatoshisPerUnitExchangeRate(3000000*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(8*startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(3000001*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(262144*startPriceSatoshis-1), int64(GetSatoshisPerUnitExchangeRate(18000000*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(33554432*startPriceSatoshis-1), int64(GetSatoshisPerUnitExchangeRate(25000000*NanosPerUnit, InitialUSDCentsPerBitcoinExchangeRate)))
	}
	// Doubling the exchange rate should double the price outputted.
	{
		startPriceSatoshis := GetStartPriceSatoshisPerDeSo(2 * InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(0, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(10, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1000, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1000000000, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(10000000000, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(100000000000, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(startPriceSatoshis+1), int64(GetSatoshisPerUnitExchangeRate(1000*NanosPerUnit, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(2*startPriceSatoshis), int64(GetSatoshisPerUnitExchangeRate(1000000*NanosPerUnit, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(16135/2-2), int64(GetSatoshisPerUnitExchangeRate(2123456*NanosPerUnit, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(8*startPriceSatoshis-1), int64(GetSatoshisPerUnitExchangeRate(3000000*NanosPerUnit, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(262144*startPriceSatoshis-1), int64(GetSatoshisPerUnitExchangeRate(18000000*NanosPerUnit, 2*InitialUSDCentsPerBitcoinExchangeRate)))
		assert.Equal(int64(33554432*startPriceSatoshis-1), int64(GetSatoshisPerUnitExchangeRate(25000000*NanosPerUnit, 2*InitialUSDCentsPerBitcoinExchangeRate)))
	}
}

func TestCalcNanosToCreate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	oldInitialUSDCentsPerBitcoinExchangeRate := InitialUSDCentsPerBitcoinExchangeRate
	InitialUSDCentsPerBitcoinExchangeRate = 1350000
	defer func() {
		InitialUSDCentsPerBitcoinExchangeRate = oldInitialUSDCentsPerBitcoinExchangeRate
	}()

	// Comment this in to test specific fields.
	//
	startNanos := uint64(8157483223947843)
	//satoshisToBurn := uint64(500000000)
	usdCentsPerBitcoin := uint64(5400000)
	xxx := float64(GetSatoshisPerUnitExchangeRate(startNanos, usdCentsPerBitcoin)) / 1e8 * float64(5700000) / 100.0
	fmt.Println(xxx)
	return

	//nanosToCreate1 := CalcNanosToCreate(
	//startNanos [>startNanos*/, satoshisToBurn /*satoshisToBurn*/, usdCentsPerBitcoin /*usdCentsPerBitcoin<])
	//fmt.Println(nanosToCreate1)
	//nanosToCreate2 := CalcNanosToCreate(
	//startNanos+nanosToCreate1 [>startNanos*/, satoshisToBurn /*satoshisToBurn*/, usdCentsPerBitcoin /*usdCentsPerBitcoin<])
	//diff := nanosToCreate1 - nanosToCreate2
	//fmt.Println(diff)
	//fmt.Println(float64(diff) / float64(nanosToCreate2))

	//startPriceSatoshisPerDeSo := GetStartPriceSatoshisPerDeSo(usdCentsPerBitcoin)
	//assert.Equal(int64(1805), int64(startPriceSatoshisPerDeSo))

	//nanosComponent := Div(NewFloat().SetUint64(NanosPerUnit), NewFloat().SetUint64(TrancheSizeNanos))
	//{
	//x, _ := nanosComponent.Float64()
	//assert.Equal(float64(1e-06), x)
	//}

	//bitcoinComponent := Div(NewFloat().SetUint64(satoshisToBurn), NewFloat().SetUint64(startPriceSatoshisPerDeSo))
	//{
	//x, _ := bitcoinComponent.Float64()
	//assert.Equal(float64(5.511003236565097e+06), x)
	//}

	//bigFloatFinalDeSoNanos := Mul(NewFloat().SetUint64(TrancheSizeNanos), BigFloatLog2(
	//Add(Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)),
	//BigFloatPow(BigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos))))))

	//{
	//x, _ := Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos)).Float64()
	//assert.Equal(float64(29.525895384803288), x)
	//}
	//{
	//fmt.Println("RIGHT BEFORE FAILING TEST")
	//x, _ := BigFloatPow(BigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos))).Float64()
	//fmt.Println("RIGHT AFTER FAILING TEST")
	//assert.Equal(float64(7.730011849578111e+08), x)
	//}
	//{
	//x, _ := Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)).Float64()
	//assert.Equal(float64(3.8199363554818304), x)
	//}
	//{
	//x, _ := Add(Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)),
	//BigFloatPow(BigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos)))).Float64()
	//assert.Equal(float64(7.730011887777475e+08), x)
	//}
	//{
	//x, _ := BigFloatLog2(
	//Add(Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)),
	//BigFloatPow(BigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos))))).Float64()
	//assert.Equal(float64(29.52589539193265), x)
	//}
	//{
	//x, _ := Mul(NewFloat().SetUint64(TrancheSizeNanos), BigFloatLog2(
	//Add(Mul(nanosComponent, Mul(bitcoinComponent, NaturalLogOfTwo)),
	//BigFloatPow(BigTwo, Div(NewFloat().SetUint64(startNanos), NewFloat().SetUint64(TrancheSizeNanos)))))).Float64()
	//assert.Equal(float64(2.9525895391932652e+16), x)
	//}

	//{
	//x, _ := bigFloatFinalDeSoNanos.Float64()
	//assert.Equal(float64(2.9525895391932652e+16), x)
	//}
	//require.Equal(int64(7129365), int64(nanosToCreate))
	//}

	{
		for ii := 0; ii < len(randomStartNanos); ii++ {
			nanosToCreate := CalcNanosToCreate(
				randomStartNanos[ii] /*startNanos*/, randomSatoshisToBurn[ii] /*satoshisToBurn*/, randomUsdCentsPerBitcoinExchangeRate[ii] /*usdCentsPerBitcoin*/)

			//if nanosToCreate == 7129365 {
			//fmt.Println("DELETEME: xxx")
			//fmt.Println(randomStartNanos[ii] [>startNanos*/, randomSatoshisToBurn[ii] /*satoshisToBurn*/, randomUsdCentsPerBitcoinExchangeRate[ii] /*usdCentsPerBitcoin<])
			//}

			calcDiff := int64(expectedRandomNanosToCreate[ii]) - int64(nanosToCreate)
			assert.Equalf(int64(expectedRandomNanosToCreate[ii]), int64(nanosToCreate), "Off by: %v", calcDiff)
			require.Less(math.Abs(float64(calcDiff)), float64(16), "Error too large")
		}

		// Run this to regenerate the supplydata_test.go data. Make sure you delete the
		// data in that file first, though.
		//
		//for startNanosIter := uint64(0); startNanosIter < 30000000*1e9; startNanosIter += 500000 * 1e9 {
		//for satoshisToBurnIter := uint64(10); satoshisToBurnIter < 100*1e8; satoshisToBurnIter += 1e8 {
		//for usdCentsPerBitcoinExchangeRateIter := uint64(100); usdCentsPerBitcoinExchangeRateIter < 100000*100; usdCentsPerBitcoinExchangeRateIter += 2500 * 100 {
		//startNanos := startNanosIter + uint64(float64(500000*1e9*rand.Float64()))
		//satoshisToBurn := satoshisToBurnIter + uint64(float64(1e8*rand.Float64()))
		//usdCentsPerBitcoinExchangeRate := usdCentsPerBitcoinExchangeRateIter + uint64(float64(1000*100*rand.Float64()))

		//// Zero satoshi means zero nanos
		//nanosToCreate := CalcNanosToCreate(
		//startNanos [>startNanos*/, satoshisToBurn /*satoshisToBurn*/, usdCentsPerBitcoinExchangeRate /*usdCentsPerBitcoin<])

		//randomStartNanos = append(randomStartNanos, startNanos)
		//randomSatoshisToBurn = append(randomSatoshisToBurn, satoshisToBurn)
		//randomUsdCentsPerBitcoinExchangeRate = append(randomUsdCentsPerBitcoinExchangeRate, usdCentsPerBitcoinExchangeRate)
		//expectedRandomNanosToCreate = append(expectedRandomNanosToCreate, nanosToCreate)
		//}
		//}
		//}
	}

	// Run this to regenerate the supplydata_test.go data. Make sure you delete the
	// data in that file first, though.
	//
	//fmt.Println("StartNanos")
	//for ii := 0; ii < len(randomStartNanos); ii++ {
	//fmt.Printf("%v, ", randomStartNanos[ii])
	//}
	//fmt.Println("\nSatoshisToBurn")
	//for ii := 0; ii < len(randomStartNanos); ii++ {
	//fmt.Printf("%v, ", randomSatoshisToBurn[ii])
	//}
	//fmt.Println("\nusdCentsPerBitcoinExchangeRate")
	//for ii := 0; ii < len(randomStartNanos); ii++ {
	//fmt.Printf("%v, ", randomUsdCentsPerBitcoinExchangeRate[ii])
	//}
	//fmt.Println("\nnanosToCreate")
	//for ii := 0; ii < len(randomStartNanos); ii++ {
	//fmt.Printf("%v, ", expectedRandomNanosToCreate[ii])
	//}

	{
		// Zero satoshi means zero nanos
		nanosToCreate := CalcNanosToCreate(
			945603607309490 /*startNanos*/, 650000000 /*satoshisToBurn*/, 1550000 /*usdCentsPerBitcoin*/)
		assert.Equal(int64(101026173281102), int64(nanosToCreate))
	}
	{
		// Zero satoshi means zero nanos
		nanosToCreate := CalcNanosToCreate(
			1046606985637137 /*startNanos*/, 1287001287 /*satoshisToBurn*/, 1554000 /*usdCentsPerBitcoin*/)
		assert.Equal(int64(181730399315476), int64(nanosToCreate))
	}
	{
		// Zero satoshi means zero nanos
		nanosToCreate := CalcNanosToCreate(0, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		// This amount of satoshis should print zero nanos at this price.
		nanosToCreate := CalcNanosToCreate(10, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		// Zero satoshi means zero nanos: second tranche
		nanosToCreate := CalcNanosToCreate(1000001*NanosPerUnit, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		// Zero satoshis should print zero nanos, even when the supply is very large.
		nanosToCreate := CalcNanosToCreate(18000001*NanosPerUnit, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		// Zero satoshis should print zero nanos, even when the supply is very large.
		nanosToCreate := CalcNanosToCreate(25000001*NanosPerUnit, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		// One satoshi should print zero nanos when the supply is large.
		nanosToCreate := CalcNanosToCreate(18000001*NanosPerUnit, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		nanosToCreate := CalcNanosToCreate(10000001*NanosPerUnit, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(262), int64(nanosToCreate))
	}
	{
		// <131 satoshis should not hurdle the threshold.
		nanosToCreate := CalcNanosToCreate(20000001*NanosPerUnit, 125, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// >131 satoshis should hurdle the threshold and print some.
		nanosToCreate := CalcNanosToCreate(18000001*NanosPerUnit, 135, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(140), int64(nanosToCreate))
	}
	{
		// One satoshi should print zero nanos when the supply is large.
		nanosToCreate := CalcNanosToCreate(25000001*NanosPerUnit, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(uint64(0), nanosToCreate)
	}
	{
		// One satoshi should print X minus the discount initially.
		nanosToCreate := CalcNanosToCreate(0*NanosPerUnit, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(270051), int64(nanosToCreate))
	}
	{
		// One satoshi should print X minus the discount initially.
		nanosToCreate := CalcNanosToCreate(10*NanosPerUnit, 10, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(2700494), int64(nanosToCreate))
	}
	{
		// Print 1 BTC at the beginning. Should be about 10k DeSo, but less
		// than that because the price is increasing slightly as they buy it.
		nanosToCreate := CalcNanosToCreate(0*NanosPerUnit, satoshisPerBitcoin+1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(26755493480681), int64(nanosToCreate))
	}
	{
		// The first purchase should work even if it's large.
		nanosToCreate := CalcNanosToCreate(0*NanosPerUnit, 200*satoshisPerBitcoin+1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(2246014623084247), int64(nanosToCreate))
	}
	{
		// Making a purchase part-way through the first tranche should work. Should
		// cost <10k but not too much less than that.
		nanosToCreate := CalcNanosToCreate(200001*NanosPerUnit, satoshisPerBitcoin+1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(23319824667603), int64(nanosToCreate))
	}
	{
		// Make a large purchase partway through the first tranche.
		nanosToCreate := CalcNanosToCreate(200001*NanosPerUnit, 200*satoshisPerBitcoin+1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(2090542905078737), int64(nanosToCreate))
	}
	{
		// A purchase part-way through a middle tranche should work.
		nanosToCreate := CalcNanosToCreate(6123456123456789, 5712345678, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(21958743502996), int64(nanosToCreate))
	}

	{
		startVal := uint64(6123456123456789)
		nanosToCreate := CalcNanosToCreate(startVal, 560988080987, InitialUSDCentsPerBitcoinExchangeRate)
		// Be careful: Your calculator will lose precision when you try to calculate this
		// to check it if you let it do floating point at any step.
		assert.Equal(int64(7448955216307525), int64(nanosToCreate)+int64(startVal))
	}

	{
		// Try a weird situation where there is less than one satoshi left worth of nanos
		// at the end of a tranche and the purchaser tries to buy zero satoshis. This should
		// result in zero nanos being created.
		startVal := uint64(7000000000000000 - 99)
		nanosToCreate := CalcNanosToCreate(startVal, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a weird situation where there is less than one satoshi left worth of nanos
		// at the end of a tranche and the purchaser tries to buy one satoshi worth of nanos.
		startVal := uint64(7000000000000000 - 99)
		nanosToCreate := CalcNanosToCreate(startVal, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(2111), int64(nanosToCreate))
	}
	{
		startVal := uint64(16000000123456789)
		satoshisToCleanOutTranche := uint64(655359919091358)
		nanosToCreate := CalcNanosToCreate(startVal, satoshisToCleanOutTranche, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(17521981851378602), int64(startVal+nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and zero satoshis are burned.
		startVal := uint64(16999999999999998)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		nanosToCreate := CalcNanosToCreate(startVal, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and 1 satoshi is burned. This should result in zero since it doesn't hurdle
		// the floating point threshold.
		startVal := uint64(16999999999999998)
		nanosToCreate := CalcNanosToCreate(startVal, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and 2 satoshi is burned. Should still be zero.
		startVal := uint64(16999999999999998)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		nanosToCreate := CalcNanosToCreate(startVal, 2, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche right at the end
		// and 3 satoshi is burned. In this case we should not cross the threshold.
		startVal := uint64(16999999999999998)
		nanosToCreate := CalcNanosToCreate(startVal, 3, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche and buys just *beyond*
		// the end (i.e. fully completes the last tranche).
		startVal := uint64(16000000123456789)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		satoshisToCleanOutTranche := uint64(655359919091359)
		nanosToCreate := CalcNanosToCreate(startVal, satoshisToCleanOutTranche, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(17521981851378602), int64(startVal+nanosToCreate))
	}
	{
		// Try a situation where a user starts in the last tranche and buys way *beyond*
		// the end (i.e. fully completes the last tranche).
		startVal := uint64(16000000123456789)
		// satoshisPerUnit := uint64(655360000)
		// (17000000*NanosPerUnit - startVal) * satoshisPerUnit / NanosPerUnit
		satoshisToCleanOutTranche := uint64(665359919091359)
		nanosToCreate := CalcNanosToCreate(startVal, satoshisToCleanOutTranche, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(17536259392211874), int64(startVal+nanosToCreate))
	}
	{
		// Try a situation where a user starts at the end and buys zero. Should result
		// in no nanos being created.
		startVal := uint64(17000000000000000)
		nanosToCreate := CalcNanosToCreate(startVal, 0, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts at the end and burns one satoshi. Should result
		// in no nanos being created.
		startVal := uint64(17000000000000000)
		nanosToCreate := CalcNanosToCreate(startVal, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Try a situation where a user starts beyond the end and burns one satoshi.
		// Should never happen but should result in no nanos being created nevertheless.
		startVal := uint64(17000000000000001)
		nanosToCreate := CalcNanosToCreate(startVal, 1, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Equal(int64(0), int64(nanosToCreate))
	}
	{
		// Spending a million Bitcoin at the max should be near-zero
		startVal := uint64(MaxNanos)
		nanosToCreate := CalcNanosToCreate(startVal, 1000000*100000000, InitialUSDCentsPerBitcoinExchangeRate)
		assert.Greater(int64(100*NanosPerUnit), int64(nanosToCreate))
	}
}

func TestBigFloat(t *testing.T) {
	//assert := assert.New(t)
	require := require.New(t)

	require.Equal(NewFloat().SetFloat64(0.33403410169116804), BigFloatPow(NewFloat().SetFloat64(0.6938468198960861), NewFloat().SetUint64(uint64(3))))
}

func TestSumBalances(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Balances should sum to the amount purchased.
	params := &DeSoMainnetParams
	amounts := uint64(0)
	balancesByPublicKey := make(map[string]int64)
	for _, seedBal := range params.SeedBalances {
		amounts += seedBal.AmountNanos
		pkStr := PkToStringMainnet(seedBal.PublicKey)
		if amountFound, exists := balancesByPublicKey[pkStr]; exists {
			require.Fail(fmt.Sprintf("Public key %v found twice in map: %v %v",
				pkStr, int64(seedBal.AmountNanos), int64(amountFound)))
		}
		balancesByPublicKey[pkStr] = int64(seedBal.AmountNanos)
	}
	require.Equal(int64(params.DeSoNanosPurchasedAtGenesis)+int64(2e6*NanosPerUnit), int64(amounts))

	// Spot-check a few balances
	_checkBalance := func(pkStr string, expectedVal int64) {
		val, exists := balancesByPublicKey[pkStr]
		assert.Truef(exists, "Public key %v must exist in genesis block", pkStr)
		assert.Equal(expectedVal, int64(val))
	}

	_checkBalance("BC1YLjAkTwNw5AKy1TCHT8qjZjmdEojvtNpB7wgFdguZ78scMu3KeBo", 285857902913000)
	_checkBalance("BC1YLhX3HZsZKYyJiv8aaoAdR5mgtf87RUiC2PyFDUFaRT7cMhtNiep", 8333340003200)
	_checkBalance("BC1YLfqL4neTSBPiiURxTyajt1y1jhkqG4qUHqEuYDtZwDD2mPo3ff6", 2888778956800)
	_checkBalance("BC1YLjTYqQV5CfH3ckQZAdwdbkEu1uSWJg1FNBu6CmL3DQZJwLceHXH", 267648349450008)
	_checkBalance("BC1YLiYxGdXeuPc3QMzgBv26EwfxrpwemdGxGZAZbh5qXgf7DennfhL", 379387259042300)
	_checkBalance("BC1YLgnKq3aJ9SL7zmiMexjRRqvenLeHQoVNRKnbCiNM4QxPgn9QU1q", 91625252862600)
	_checkBalance("BC1YLitnSuYscJ2GyHt9g3SfQKWz5ht1Ee5LUxBNk22Jo8Cde7Wupy7", 91625252862600)
	_checkBalance("BC1YLhgrsxAejRUyhYmZRexhXq3nNbBgWH45TC56rxErHCjrKEhseYq", 166000000000000)
	_checkBalance("BC1YLgGUvSCBToN9gbThF3cETR4B2dhcaFBTyUy64NCmY4Y483WfHUX", 30000000000000)
	_checkBalance("BC1YLg26dcBA1HjTkDwXPH4oog7bVGbsQKj4G6rmHkZ6o7ApUzW4S8j", 62500000000000)
}
