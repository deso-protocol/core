package lib

import (
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestBalanceLedger(t *testing.T) {
	require := require.New(t)

	pk0 := *NewPublicKey(m0PkBytes)
	pk1 := *NewPublicKey(m1PkBytes)
	pk2 := *NewPublicKey(m2PkBytes)

	// Sanity-check some balance increase and decreases for pk0
	balanceLedger := NewBalanceLedger()
	require.NoError(balanceLedger.CheckBalanceIncrease(pk0, 100, 100))
	require.NoError(balanceLedger.CheckBalanceIncrease(pk0, 0, 100))
	balanceLedger.IncreaseBalance(pk0, 100)
	require.Equal(uint64(100), balanceLedger.GetBalance(pk0))
	require.NoError(balanceLedger.CheckBalanceIncrease(pk0, 0, 100))
	require.Error(balanceLedger.CheckBalanceIncrease(pk0, 1, 100))
	require.Error(balanceLedger.CheckBalanceIncrease(pk0, 0, 99))
	require.Error(balanceLedger.CheckBalanceIncrease(pk0, math.MaxUint64, math.MaxUint64))
	require.NoError(balanceLedger.CheckBalanceDecrease(pk0, 100))
	require.NoError(balanceLedger.CheckBalanceDecrease(pk0, 0))
	require.Error(balanceLedger.CheckBalanceDecrease(pk0, 101))
	require.Error(balanceLedger.CheckBalanceDecrease(pk0, math.MaxUint64))
	balanceLedger.DecreaseBalance(pk0, 100)
	require.Equal(uint64(0), balanceLedger.GetBalance(pk0))
	balanceLedger.IncreaseBalance(pk0, 10)
	require.Equal(uint64(10), balanceLedger.GetBalance(pk0))
	balanceLedger.DecreaseBalance(pk0, 100)
	require.Equal(uint64(0), balanceLedger.GetBalance(pk0))
	balanceLedger.IncreaseBalance(pk0, 100)

	// Increase balance for pk1 and pk2 a couple of times
	balanceLedger.IncreaseBalance(pk1, 100)
	balanceLedger.IncreaseBalance(pk2, 100)
	balanceLedger.DecreaseBalance(pk1, 40)
	balanceLedger.IncreaseBalance(pk2, 40)
	require.Equal(uint64(100), balanceLedger.GetBalance(pk0))
	require.Equal(uint64(60), balanceLedger.GetBalance(pk1))
	require.Equal(uint64(140), balanceLedger.GetBalance(pk2))

	// Test clearing balance ledger
	balanceLedger.Reset()
	require.Equal(uint64(0), balanceLedger.GetBalance(pk0))
	require.Equal(uint64(0), balanceLedger.GetBalance(pk1))
	require.Equal(uint64(0), balanceLedger.GetBalance(pk2))
}
