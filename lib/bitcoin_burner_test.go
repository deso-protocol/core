package lib

import (
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	BlockCypherTestAPIKey = "3aaa4e1c99164e8ba9ade1a605a150c0"
)

func TestCheckDoubleSpend(t *testing.T) {
	// Set up a blockchain
	assert := assert.New(t)
	require := require.New(t)
	_, _ = assert, require

	// Mainnet checks
	{
		params := &DeSoMainnetParams

		// This txn is not a double-spend
		{
			hash, err := chainhash.NewHashFromStr("4d02fa8bed28405dd0f8eabbcd5a1ead6018ee7d260d026bb9ba99eb90f7389b")
			require.NoError(err)
			isDoubleSpend, err := BlockCypherCheckBitcoinDoubleSpend(hash, BlockCypherTestAPIKey, params)
			require.NoError(err)
			require.False(isDoubleSpend)
		}
		{
			hash, err := chainhash.NewHashFromStr("60bbed01b7d6adfe1482161092894943e4ddff9cc9c9ed398df295cfcfde2d9e")
			require.NoError(err)
			isDoubleSpend, err := BlockCypherCheckBitcoinDoubleSpend(hash, BlockCypherTestAPIKey, params)
			require.NoError(err)
			require.True(isDoubleSpend)
		}
	}

	{
		// Testnet checks
		params := &DeSoTestnetParams

		// This txn is not a double-spend
		{
			hash, err := chainhash.NewHashFromStr("141efaf43d716166792dec365b5b598a0ad9920baf52446675840c4b3ea2e4e1")
			require.NoError(err)
			isDoubleSpend, err := BlockCypherCheckBitcoinDoubleSpend(hash, BlockCypherTestAPIKey, params)
			require.NoError(err)
			require.False(isDoubleSpend)
		}
		{
			hash, err := chainhash.NewHashFromStr("60bbed01b7d6adfe1482161092894943e4ddff9cc9c9ed398df295cfcfde2d9e")
			require.NoError(err)
			isDoubleSpend, err := BlockCypherCheckBitcoinDoubleSpend(hash, BlockCypherTestAPIKey, params)
			require.NoError(err)
			require.True(isDoubleSpend)
		}
	}
}

// Comment this in to test the RBF checker. We comment it out for now since the transactions
// used within it go stale and return different values after being mined.
//
//func TestCheckRBF(t *testing.T) {
//
//	// Set up a blockchain
//	assert := assert.New(t)
//	require := require.New(t)
//	_, _ = assert, require
//
//	{
//		isRBF, err := BlockonomicsCheckRBF("625ae824aaa832731fbd124d10e54e7e976083ef91da81f51f80838f0e442df6")
//		require.NoError(err)
//		require.True(isRBF)
//	}
//
//	{
//		isRBF, err := BlockonomicsCheckRBF("42239441b091f78185ee398cdbdc4f9710ccf2c309175b5f47cd189429f7552b")
//		require.NoError(err)
//		require.False(isRBF)
//	}
//}
