package consensus

import "fmt"

func (eventType FastHotStuffEventType) ToString() string {
	switch eventType {
	case FastHotStuffEventTypeVote:
		return "VOTE"
	case FastHotStuffEventTypeTimeout:
		return "TIMEOUT"
	case FastHotStuffEventTypeConstructVoteQC:
		return "VOTE_QC"
	case FastHotStuffEventTypeConstructTimeoutQC:
		return "TIMEOUT_QC"
	}
	return "UNKNOWN"
}

func (event *FastHotStuffEvent) ToString() string {
	return fmt.Sprintf(
		"{Type: %s, View: %d, Height: %d}",
		event.EventType.ToString(),
		event.View,
		event.TipBlockHeight,
	)
}
