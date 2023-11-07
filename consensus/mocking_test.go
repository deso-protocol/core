package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFastHotStuffEventLoopMockType(t *testing.T) {
	var eventLoop FastHotStuffEventLoop
	eventLoop = &MockFastHotStuffEventLoop{}

	// Verify that the mock struct implements the interface type
	require.True(t, !isInterfaceNil(eventLoop))
}
