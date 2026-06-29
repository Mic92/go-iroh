package gossip

import "testing"

func TestTopicLaggedClosesSubscriber(t *testing.T) {
	topic := &Topic{events: make(chan Event, 1)}
	topic.sendEvent(Event{Kind: NeighborUp})
	topic.sendEvent(Event{Kind: Received})

	ev, ok := <-topic.events
	if !ok {
		t.Fatal("events closed before Lagged")
	}
	if ev.Kind != Lagged {
		t.Fatalf("event = %v, want Lagged", ev.Kind)
	}
	if _, ok := <-topic.events; ok {
		t.Fatal("events still open after Lagged")
	}
}
