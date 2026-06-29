package gossipproto

import (
	"reflect"
	"testing"
	"time"
)

func TestPlumtreeStateGossip(t *testing.T) {
	now := time.Unix(1, 0)
	me := PeerID(seq32(1))
	from := PeerID(seq32(2))
	lazy := PeerID(seq32(3))
	content := []byte("hello")
	id := MessageIDFromContent(content)

	state := NewPlumtreeState(me, DefaultPlumtreeConfig())
	state.addLazy(lazy)

	got := state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: from,
		Now:  now,
		Message: PlumtreeMessage{
			Kind: PlumtreeGossip,
			Gossip: Gossip{
				ID:      id,
				Content: content,
				Scope:   DeliveryScope{Kind: DeliveryScopeSwarm, Round: 1},
			},
		},
	})
	want := []PlumtreeOutEvent{
		{
			Kind:  PlumtreeScheduleTimer,
			After: time.Second,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerEvictCache},
		},
		{
			Kind:  PlumtreeScheduleTimer,
			After: 5 * time.Millisecond,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerDispatchLazyPush},
		},
		{
			Kind: PlumtreeEmitEvent,
			Event: PlumtreeEvent{
				Kind:          PlumtreeReceived,
				Content:       content,
				DeliveredFrom: from,
				Scope:         DeliveryScope{Kind: DeliveryScopeSwarm, Round: 1},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Handle = %#v, want %#v", got, want)
	}

	got = state.Handle(PlumtreeInEvent{
		Kind:  PlumtreeTimerExpired,
		Timer: PlumtreeTimer{Kind: PlumtreeTimerDispatchLazyPush},
		Now:   now,
	})
	want = []PlumtreeOutEvent{
		{
			Kind: PlumtreeSendMessage,
			To:   lazy,
			Message: PlumtreeMessage{
				Kind:  PlumtreeIHave,
				IHave: []IHave{{ID: id, Round: 2}},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("dispatch = %#v, want %#v", got, want)
	}
}

func TestPlumtreeStateRejectsSpoofedGossip(t *testing.T) {
	state := NewPlumtreeState(PeerID(seq32(1)), DefaultPlumtreeConfig())
	got := state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: PeerID(seq32(2)),
		Now:  time.Unix(1, 0),
		Message: PlumtreeMessage{
			Kind: PlumtreeGossip,
			Gossip: Gossip{
				ID:      MessageIDFromContent([]byte("other")),
				Content: []byte("hello"),
				Scope:   DeliveryScope{Kind: DeliveryScopeSwarm, Round: 1},
			},
		},
	})
	want := []PlumtreeOutEvent{{
		Kind:  PlumtreeScheduleTimer,
		After: time.Second,
		Timer: PlumtreeTimer{Kind: PlumtreeTimerEvictCache},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Handle = %#v, want %#v", got, want)
	}
}

func TestPlumtreeStateDuplicateGossipPrunesSender(t *testing.T) {
	now := time.Unix(1, 0)
	me := PeerID(seq32(1))
	from := PeerID(seq32(2))
	content := []byte("hello")
	id := MessageIDFromContent(content)
	state := NewPlumtreeState(me, DefaultPlumtreeConfig())
	state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: from,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:   PlumtreeGossip,
			Gossip: Gossip{ID: id, Content: content, Scope: DeliveryScope{Kind: DeliveryScopeSwarm}},
		},
	})

	got := state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: from,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:   PlumtreeGossip,
			Gossip: Gossip{ID: id, Content: content, Scope: DeliveryScope{Kind: DeliveryScopeSwarm}},
		},
	})
	want := []PlumtreeOutEvent{{
		Kind:    PlumtreeSendMessage,
		To:      from,
		Message: PlumtreeMessage{Kind: PlumtreePrune},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Handle duplicate = %#v, want %#v", got, want)
	}
	if _, ok := state.lazy[from]; !ok {
		t.Fatalf("duplicate sender not moved to lazy set")
	}
}

func TestPlumtreeStateIHaveSchedulesAndGrafts(t *testing.T) {
	now := time.Unix(1, 0)
	me := PeerID(seq32(1))
	from := PeerID(seq32(2))
	id := MessageIDFromContent([]byte("hello"))
	state := NewPlumtreeState(me, DefaultPlumtreeConfig())

	got := state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: from,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:  PlumtreeIHave,
			IHave: []IHave{{ID: id, Round: 4}},
		},
	})
	want := []PlumtreeOutEvent{
		{
			Kind:  PlumtreeScheduleTimer,
			After: time.Second,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerEvictCache},
		},
		{
			Kind:  PlumtreeScheduleTimer,
			After: 80 * time.Millisecond,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerSendGraft, ID: id},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IHave = %#v, want %#v", got, want)
	}

	got = state.Handle(PlumtreeInEvent{
		Kind:  PlumtreeTimerExpired,
		Timer: PlumtreeTimer{Kind: PlumtreeTimerSendGraft, ID: id},
		Now:   now,
	})
	wantID := id
	want = []PlumtreeOutEvent{
		{
			Kind: PlumtreeSendMessage,
			To:   from,
			Message: PlumtreeMessage{
				Kind:  PlumtreeGraft,
				Graft: Graft{ID: &wantID, Round: 4},
			},
		},
		{
			Kind:  PlumtreeScheduleTimer,
			After: 40 * time.Millisecond,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerSendGraft, ID: id},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SendGraft timer = %#v, want %#v", got, want)
	}
	if _, ok := state.eager[from]; !ok {
		t.Fatalf("graft target not moved to eager set")
	}
}

func TestPlumtreeStateDispatchChunksIHave(t *testing.T) {
	me := PeerID(seq32(1))
	peer := PeerID(seq32(2))
	config := DefaultPlumtreeConfig()
	config.MaxPayloadSize = 3 + 2*iHavePostcardMaxSize
	state := NewPlumtreeState(me, config)
	state.lazyQueue[peer] = []IHave{
		{ID: MessageID(seq32(10)), Round: 1},
		{ID: MessageID(seq32(11)), Round: 2},
		{ID: MessageID(seq32(12)), Round: 3},
		{ID: MessageID(seq32(13)), Round: 4},
		{ID: MessageID(seq32(14)), Round: 5},
	}
	state.dispatchTimerScheduled = true

	var got []PlumtreeOutEvent
	state.onDispatchTimer(&got)
	if len(got) != 3 {
		t.Fatalf("dispatch emitted %d events, want 3: %#v", len(got), got)
	}
	lengths := []int{
		len(got[0].Message.IHave),
		len(got[1].Message.IHave),
		len(got[2].Message.IHave),
	}
	if !reflect.DeepEqual(lengths, []int{2, 2, 1}) {
		t.Fatalf("IHave chunk lengths = %v, want [2 2 1]", lengths)
	}
	if len(state.lazyQueue) != 0 {
		t.Fatalf("lazyQueue len = %d, want 0", len(state.lazyQueue))
	}
	if state.dispatchTimerScheduled {
		t.Fatal("dispatchTimerScheduled still true")
	}
}

func TestPlumtreeStateGraftRepliesFromCache(t *testing.T) {
	now := time.Unix(1, 0)
	me := PeerID(seq32(1))
	from := PeerID(seq32(2))
	requester := PeerID(seq32(3))
	content := []byte("hello")
	id := MessageIDFromContent(content)
	state := NewPlumtreeState(me, DefaultPlumtreeConfig())
	state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: from,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:   PlumtreeGossip,
			Gossip: Gossip{ID: id, Content: content, Scope: DeliveryScope{Kind: DeliveryScopeSwarm, Round: 1}},
		},
	})

	got := state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: requester,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:  PlumtreeGraft,
			Graft: Graft{ID: &id, Round: 1},
		},
	})
	want := []PlumtreeOutEvent{{
		Kind: PlumtreeSendMessage,
		To:   requester,
		Message: PlumtreeMessage{
			Kind: PlumtreeGossip,
			Gossip: Gossip{
				ID:      id,
				Content: content,
				Scope:   DeliveryScope{Kind: DeliveryScopeSwarm, Round: 2},
			},
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Graft = %#v, want %#v", got, want)
	}
}

func TestPlumtreeStateOptimizeTree(t *testing.T) {
	now := time.Unix(1, 0)
	me := PeerID(seq32(1))
	ihavePeer := PeerID(seq32(2))
	gossipPeer := PeerID(seq32(3))
	state := NewPlumtreeState(me, DefaultPlumtreeConfig())

	content := []byte("hi")
	id := MessageIDFromContent(content)
	state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: ihavePeer,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:  PlumtreeIHave,
			IHave: []IHave{{ID: id, Round: 2}},
		},
	})
	got := state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: gossipPeer,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:   PlumtreeGossip,
			Gossip: Gossip{ID: id, Content: content, Scope: DeliveryScope{Kind: DeliveryScopeSwarm, Round: 6}},
		},
	})
	want := []PlumtreeOutEvent{
		{
			Kind:  PlumtreeScheduleTimer,
			After: 5 * time.Millisecond,
			Timer: PlumtreeTimer{Kind: PlumtreeTimerDispatchLazyPush},
		},
		{
			Kind: PlumtreeEmitEvent,
			Event: PlumtreeEvent{
				Kind:          PlumtreeReceived,
				Content:       content,
				DeliveredFrom: gossipPeer,
				Scope:         DeliveryScope{Kind: DeliveryScopeSwarm, Round: 6},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no optimization = %#v, want %#v", got, want)
	}

	content = []byte("hi2")
	id = MessageIDFromContent(content)
	state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: ihavePeer,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:  PlumtreeIHave,
			IHave: []IHave{{ID: id, Round: 2}},
		},
	})
	got = state.Handle(PlumtreeInEvent{
		Kind: PlumtreeRecvMessage,
		From: gossipPeer,
		Now:  now,
		Message: PlumtreeMessage{
			Kind:   PlumtreeGossip,
			Gossip: Gossip{ID: id, Content: content, Scope: DeliveryScope{Kind: DeliveryScopeSwarm, Round: 9}},
		},
	})
	want = []PlumtreeOutEvent{
		{
			Kind: PlumtreeSendMessage,
			To:   ihavePeer,
			Message: PlumtreeMessage{
				Kind:  PlumtreeGraft,
				Graft: Graft{Round: 2},
			},
		},
		{
			Kind:    PlumtreeSendMessage,
			To:      gossipPeer,
			Message: PlumtreeMessage{Kind: PlumtreePrune},
		},
		{
			Kind: PlumtreeEmitEvent,
			Event: PlumtreeEvent{
				Kind:          PlumtreeReceived,
				Content:       content,
				DeliveredFrom: gossipPeer,
				Scope:         DeliveryScope{Kind: DeliveryScopeSwarm, Round: 9},
			},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("optimization = %#v, want %#v", got, want)
	}
}
