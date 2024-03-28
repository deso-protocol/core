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
	require.NoError(balanceLedger.CanIncreaseEntryWithLimit(pk0, 100, 100))
	require.NoError(balanceLedger.CanIncreaseEntryWithLimit(pk0, 0, 100))
	balanceLedger.IncreaseEntry(pk0, 100)
	require.Equal(uint64(100), balanceLedger.GetEntry(pk0))
	require.NoError(balanceLedger.CanIncreaseEntryWithLimit(pk0, 0, 100))
	require.Error(balanceLedger.CanIncreaseEntryWithLimit(pk0, 1, 100))
	require.Error(balanceLedger.CanIncreaseEntryWithLimit(pk0, 0, 99))
	require.Error(balanceLedger.CanIncreaseEntryWithLimit(pk0, math.MaxUint64, math.MaxUint64))
	balanceLedger.DecreaseEntry(pk0, 100)
	require.Equal(uint64(0), balanceLedger.GetEntry(pk0))
	balanceLedger.IncreaseEntry(pk0, 10)
	require.Equal(uint64(10), balanceLedger.GetEntry(pk0))
	balanceLedger.DecreaseEntry(pk0, 100)
	require.Equal(uint64(0), balanceLedger.GetEntry(pk0))
	balanceLedger.IncreaseEntry(pk0, 100)

	// Increase balance for pk1 and pk2 a couple of times
	balanceLedger.IncreaseEntry(pk1, 100)
	balanceLedger.IncreaseEntry(pk2, 100)
	balanceLedger.DecreaseEntry(pk1, 40)
	balanceLedger.IncreaseEntry(pk2, 40)
	require.Equal(uint64(100), balanceLedger.GetEntry(pk0))
	require.Equal(uint64(60), balanceLedger.GetEntry(pk1))
	require.Equal(uint64(140), balanceLedger.GetEntry(pk2))

	// Test clearing balance ledger
	balanceLedger.Reset()
	require.Equal(uint64(0), balanceLedger.GetEntry(pk0))
	require.Equal(uint64(0), balanceLedger.GetEntry(pk1))
	require.Equal(uint64(0), balanceLedger.GetEntry(pk2))
}
