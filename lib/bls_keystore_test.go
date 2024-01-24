//go:build relic

package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewBLSKeystore(t *testing.T) {
	// Test empty string
	{
		_, err := NewBLSKeystore("")
		require.Error(t, err)
	}

	// Test invalid seed phrase
	{
		_, err := NewBLSKeystore("invalid seed phrase")
		require.Error(t, err)
	}

	// Test valid 12 word seed phrase
	{
		keystore, err := NewBLSKeystore("suit three minute series empty virtual snake safe joke gold pear emerge")
		require.NoError(t, err)
		require.Equal(t, keystore.GetSigner().privateKey.ToString(), "0x2000bd5d14801e3a96f27a25ae4ebd26ec08a67c207b04c21703b40d80b8de71")
	}

	// Test valid 24 word seed phrase
	{
		keystore, err := NewBLSKeystore("vapor educate wood post fiber proof cannon chunk luggage hedgehog merit dove network lemon scorpion job law more salt market excuse auction refuse apart")
		require.NoError(t, err)
		require.NoError(t, err)
		require.Equal(t, keystore.GetSigner().privateKey.ToString(), "0x13b5febb384a3d3dec5c579724872607cd0ddb97adef592efaf144f6d25a70d7")
	}
}
