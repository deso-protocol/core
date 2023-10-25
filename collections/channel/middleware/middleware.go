package middleware

import (
	mo "github.com/deso-protocol/core/collections/channel/message_origin"
)

type Middleware[Message any, Origin any] struct {
	inputChan     chan Message
	outputChan    chan *mo.MessageOrigin[Message, Origin]
	messageOrigin Origin

	quitChan chan struct{}
}

func NewMiddleware[Message any, Origin any](inputChan chan Message, outputChan chan *mo.MessageOrigin[Message, Origin],
	messageOrigin Origin) *Middleware[Message, Origin] {

	cm := &Middleware[Message, Origin]{
		inputChan:     inputChan,
		outputChan:    outputChan,
		messageOrigin: messageOrigin,
		quitChan:      make(chan struct{}),
	}
	return cm
}

func (cm *Middleware[Message, Origin]) Start() {
	go func() {
		for {
			select {
			case msg, ok := <-cm.inputChan:
				if !ok {
					return
				}
				cm.outputChan <- mo.NewMessageOrigin[Message, Origin](msg, cm.messageOrigin)
			case <-cm.quitChan:
				return
			}
		}
	}()
}

func (cm *Middleware[Message, Origin]) Stop() {
	close(cm.quitChan)
}
