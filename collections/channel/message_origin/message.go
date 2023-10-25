package message_origin

type MessageOrigin[Message any, Origin any] struct {
	message Message
	origin  Origin
}

func NewMessageOrigin[Message any, Origin any](message Message, origin Origin) *MessageOrigin[Message, Origin] {
	return &MessageOrigin[Message, Origin]{
		message: message,
		origin:  origin,
	}
}

func (cmo *MessageOrigin[Message, Origin]) GetOrigin() Origin {
	return cmo.origin
}

func (cmo *MessageOrigin[Message, Origin]) GetMessage() Message {
	return cmo.message
}
