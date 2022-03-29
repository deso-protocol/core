package lib

import (
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	"math"
	"testing"
)

func TestSafeUint256(t *testing.T) {
	require := require.New(t)
	var result *uint256.Int
	var err error

	// Test Add(): sad path
	result, err = SafeUint256().Add(uint256.NewInt().SetUint64(1), MaxUint256)
	require.Nil(result)
	require.Error(err)
	require.Contains(err.Error(), "addition overflows uint256")

	// Test Add(): happy path
	result, err = SafeUint256().Add(uint256.NewInt().SetUint64(2), uint256.NewInt().SetUint64(2))
	require.Equal(result, uint256.NewInt().SetUint64(4))
	require.NoError(err)

	// Test Sub(): sad path
	result, err = SafeUint256().Sub(uint256.NewInt().SetUint64(1), uint256.NewInt().SetUint64(2))
	require.Nil(result)
	require.Error(err)
	require.Contains(err.Error(), "subtraction underflows uint256")

	// Test Sub(): happy path
	result, err = SafeUint256().Sub(uint256.NewInt().SetUint64(3), uint256.NewInt().SetUint64(2))
	require.Equal(result, uint256.NewInt().SetUint64(1))
	require.NoError(err)

	// Test Mul(): sad path
	result, err = SafeUint256().Mul(MaxUint256, uint256.NewInt().SetUint64(2))
	require.Nil(result)
	require.Error(err)
	require.Contains(err.Error(), "multiplication overflows uint256")

	// Test Mul(): happy path
	result, err = SafeUint256().Mul(uint256.NewInt().SetUint64(3), uint256.NewInt().SetUint64(4))
	require.Equal(result, uint256.NewInt().SetUint64(12))
	require.NoError(err)

	// Test Div(): sad path
	result, err = SafeUint256().Div(uint256.NewInt().SetUint64(3), uint256.NewInt())
	require.Nil(result)
	require.Error(err)
	require.Contains(err.Error(), "division by zero")

	// Test Div(): happy path
	result, err = SafeUint256().Div(uint256.NewInt().SetUint64(9), uint256.NewInt().SetUint64(3))
	require.Equal(result, uint256.NewInt().SetUint64(3))
	require.NoError(err)
}

func TestSafeUint64(t *testing.T) {
	require := require.New(t)
	var result uint64
	var err error

	// Test Add(): sad path
	result, err = SafeUint64().Add(uint64(1), math.MaxUint64)
	require.Zero(result)
	require.Error(err)
	require.Contains(err.Error(), "addition overflows uint64")

	// Test Add(): happy path
	result, err = SafeUint64().Add(uint64(2), uint64(2))
	require.Equal(result, uint64(4))
	require.NoError(err)

	// Test Sub(): sad path
	result, err = SafeUint64().Sub(uint64(1), uint64(2))
	require.Zero(result)
	require.Error(err)
	require.Contains(err.Error(), "subtraction underflows uint64")

	// Test Sub(): happy path
	result, err = SafeUint64().Sub(uint64(3), uint64(2))
	require.Equal(result, uint64(1))
	require.NoError(err)

	// Test Mul(): sad path
	result, err = SafeUint64().Mul(math.MaxUint64, uint64(2))
	require.Zero(result)
	require.Error(err)
	require.Contains(err.Error(), "multiplication overflows uint64")

	// Test Mul(): happy path
	result, err = SafeUint64().Mul(uint64(3), uint64(4))
	require.Equal(result, uint64(12))
	require.NoError(err)

	// Test Div(): sad path
	result, err = SafeUint64().Div(uint64(3), uint64(0))
	require.Zero(result)
	require.Error(err)
	require.Contains(err.Error(), "division by zero")

	// Test Div(): happy path
	result, err = SafeUint64().Div(uint64(9), uint64(3))
	require.Equal(result, uint64(3))
	require.NoError(err)
}
