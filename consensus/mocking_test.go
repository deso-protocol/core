package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFastHotStuffEventLoopMockStruct(t *testing.T) {
	var eventLoop FastHotStuffEventLoop
	eventLoop = &MockFastHotStuffEventLoop{}

	// Verify that the mock struct implements the interface type
	require.True(t, !isInterfaceNil(eventLoop))
}

func TestFastHotStuffEventLoopImplementationStruct(t *testing.T) {
	var eventLoop FastHotStuffEventLoop
	eventLoop = NewFastHotStuffEventLoop()

	// Verify that the implementation struct implements the interface type
	require.True(t, !isInterfaceNil(eventLoop))
}
