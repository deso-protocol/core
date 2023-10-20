package middleware

import (
	"github.com/deso-protocol/core/collections/channel/message_origin"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMiddleware(t *testing.T) {
	require := require.New(t)

	input := make(chan int, 1)
	output := make(chan *message_origin.MessageOrigin[int, int], 1)
	mw := NewMiddleware[int, int](input, output, 5)
	mw.Start()

	input <- 1
	select {
	case msg, ok := <-output:
		require.True(ok)
		require.Equal(1, msg.GetMessage())
		require.Equal(5, msg.GetOrigin())
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Timeout waiting for message")
	}

	mw.Stop()
	_, ok := <-mw.quitChan
	require.False(ok)

	// Make sure messages are not sent after middleware is stopped.
	input <- 2
	select {
	case msg, ok := <-output:
		t.Fatal("Message received after middleware stopped", msg, ok)
	case <-time.After(10 * time.Millisecond):
	}
}
