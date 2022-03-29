package lib

import (
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
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
	result, err = SafeUint256().Mul(MaxUint256, MaxUint256)
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
