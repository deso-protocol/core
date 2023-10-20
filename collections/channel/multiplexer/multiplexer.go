package multiplexer

import (
	"github.com/deso-protocol/core/collections/channel/message_origin"
	"github.com/deso-protocol/core/collections/channel/middleware"
)

type Multiplexer[Message any, Origin any] struct {
	middlewares map[uint64]*middleware.Middleware[Message, Origin]
	outputChan  chan *message_origin.MessageOrigin[Message, Origin]
}

func NewMultiplexer[Message any, Origin any](outputChan chan *message_origin.MessageOrigin[Message, Origin]) *Multiplexer[Message, Origin] {

	return &Multiplexer[Message, Origin]{
		middlewares: make(map[uint64]*middleware.Middleware[Message, Origin]),
		outputChan:  outputChan,
	}
}

func (m *Multiplexer[Message, Origin]) AddChannel(id uint64, inputChan chan Message, origin Origin) {
	mw := middleware.NewMiddleware[Message, Origin](inputChan, m.outputChan, origin)
	mw.Start()
	m.middlewares[id] = mw
}

func (m *Multiplexer[Message, Origin]) RemoveChannel(id uint64) {
	m.middlewares[id].Stop()
	delete(m.middlewares, id)
}

func (m *Multiplexer[Message, Origin]) Clear() {
	for _, mw := range m.middlewares {
		mw.Stop()
	}
	m.middlewares = make(map[uint64]*middleware.Middleware[Message, Origin])
}
