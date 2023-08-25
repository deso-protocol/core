package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFastHotStuffInitialization(t *testing.T) {

	// Test initial status for newly constructed instance
	{
		fc := NewFastHotStuffConsensus()
		require.Equal(t, consensusStatusNotRunning, fc.status)
	}

	// Test Init() function with invalid block construction cadence
	{
		fc := NewFastHotStuffConsensus()

	}
}
