package gossipproto

import (
	"reflect"
	"testing"
)

func TestStateDisconnectFansOutInTopicOrder(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	topics := []TopicID{TopicID(seq32(10)), TopicID(seq32(20)), TopicID(seq32(30)), TopicID(seq32(40))}

	// Four topics leave map order sorted 1 time in 24, and a single state
	// would only expose an unsorted fan-out about half the time. Rebuild the
	// state so that an unsorted implementation fails essentially always.
	for range 10 {
		state := NewStateWithRand(me, nil, DefaultConfig(), testRand(t))
		for _, topic := range topics {
			state.Handle(InEvent{
				Kind:    CommandEvent,
				Topic:   topic,
				Command: TopicCommand{Kind: TopicCommandJoin, Peers: []PeerID{peer}},
			})
			state.Handle(InEvent{
				Kind: RecvMessage,
				From: peer,
				Message: Message{
					Topic: topic,
					Message: TopicMessage{
						Kind:  TopicMessageSwarm,
						Swarm: HyparviewMessage{Kind: HyparviewNeighbor, Neighbor: Neighbor{Priority: PriorityHigh}},
					},
				},
			})
		}

		var got []TopicID
		for _, ev := range state.Handle(InEvent{Kind: PeerDisconnected, Peer: peer}) {
			if ev.Topic != (TopicID{}) {
				got = append(got, ev.Topic)
			}
		}
		if !reflect.DeepEqual(got, topics) {
			t.Fatalf("disconnect fan-out topics = %#v, want %#v", got, topics)
		}
	}
}
