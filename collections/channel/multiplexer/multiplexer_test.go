package multiplexer

import (
	"github.com/deso-protocol/core/collections/channel/message_origin"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMultiplexer(t *testing.T) {
	require := require.New(t)

	inputChan := make(chan int, 1)
	outputChan := make(chan *message_origin.MessageOrigin[int, int], 10)
	multiplexer := NewMultiplexer[int, int](outputChan)

	multiplexer.AddChannel(15, inputChan, 7)
	inputChan <- 1
	select {
	case msg, ok := <-outputChan:
		require.True(ok)
		require.Equal(1, msg.GetMessage())
		require.Equal(7, msg.GetOrigin())
	case <-time.After(10 * time.Millisecond):
		t.Fatal("Timeout waiting for message")
	}

	multiplexer.RemoveChannel(15)
	require.Len(multiplexer.middlewares, 0)

	inputChanA := make(chan int, 1)
	inputChanB := make(chan int, 1)
	inputChanC := make(chan int, 1)
	multiplexer.AddChannel(7, inputChanA, 0)
	multiplexer.AddChannel(8, inputChanB, 1)
	multiplexer.AddChannel(9, inputChanC, 2)
	inputChanA <- 20
	inputChanB <- 30
	inputChanC <- 40

	allOrigins := make(map[int]bool)
	for ii := 0; ii < 3; ii++ {
		allOrigins[ii] = false
	}
	for ii := 0; ii < 3; ii++ {
		select {
		case msg, ok := <-outputChan:
			require.True(ok)
			o := msg.GetOrigin()
			require.False(allOrigins[o])
			allOrigins[o] = true
			require.Equal(20+o*10, msg.GetMessage())
		case <-time.After(10 * time.Millisecond):
			t.Fatal("Timeout waiting for message")
		}
	}

	for _, ok := range allOrigins {
		require.True(ok)
	}

	multiplexer.Clear()
}
