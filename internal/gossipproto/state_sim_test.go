package gossipproto

import (
	"bytes"
	"math/rand"
	"slices"
	"testing"
	"time"
)

func TestStateChurnConvergenceSimulation(t *testing.T) {
	const n = 10
	topic := TopicID(seq32(0x20))
	sim := newStateSim(n, topic)

	sim.joinAll()
	sim.runRounds(8)
	sim.requireOverlay(t, "warmup")

	sim.remove(3)
	sim.runRounds(8)
	sim.requireOverlay(t, "churn")

	content := []byte("churn convergence")
	sim.broadcast(1, content)
	sim.runRounds(10)
	sim.requireBroadcast(t, 1, content, 4)
}

type stateSim struct {
	topic     TopicID
	now       time.Time
	config    Config
	nodes     map[PeerID]*State
	timers    map[PeerID][]Timer
	delivered map[PeerID][]TopicEvent
	queue     []stateSimMessage
}

type stateSimMessage struct {
	from    PeerID
	to      PeerID
	message Message
}

func newStateSim(n int, topic TopicID) *stateSim {
	config := DefaultConfig()
	config.Topic.Membership.ActiveViewCapacity = 3
	config.Topic.Membership.PassiveViewCapacity = 8
	config.Topic.Membership.ShuffleActiveViewCount = 2
	config.Topic.Membership.ShufflePassiveViewCount = 3
	config.Topic.Membership.ShuffleInterval = time.Second
	config.Topic.Membership.NeighborRequestTimeout = time.Millisecond

	sim := &stateSim{
		topic:     topic,
		now:       time.Unix(1, 0),
		config:    config,
		nodes:     make(map[PeerID]*State),
		timers:    make(map[PeerID][]Timer),
		delivered: make(map[PeerID][]TopicEvent),
	}
	for i := range n {
		id := sim.peer(i)
		sim.nodes[id] = NewStateWithRand(id, nil, config, rand.New(rand.NewSource(int64(i+1))))
	}
	return sim
}

func (s *stateSim) peer(i int) PeerID {
	return PeerID(seq32(byte(0x40 + i*3)))
}

func (s *stateSim) joinAll() {
	for i := 0; i < len(s.nodes); i++ {
		id := s.peer(i)
		if s.nodes[id] == nil {
			continue
		}
		var peers []PeerID
		if i > 0 {
			peers = append(peers, s.peer(0), s.peer(i-1))
		}
		s.apply(id, s.nodes[id].Handle(InEvent{
			Kind:  CommandEvent,
			Topic: s.topic,
			Command: TopicCommand{
				Kind:  TopicCommandJoin,
				Peers: peers,
			},
			Now: s.now,
		}))
		s.drainMessages()
	}
}

func (s *stateSim) remove(i int) {
	peer := s.peer(i)
	delete(s.nodes, peer)
	delete(s.timers, peer)
	delete(s.delivered, peer)
	var out []stateSimOut
	for _, id := range sortedPeers(s.nodes) {
		node := s.nodes[id]
		out = append(out, stateSimOut{id: id, events: node.Handle(InEvent{
			Kind: PeerDisconnected,
			Peer: peer,
			Now:  s.now,
		})})
	}
	for _, item := range out {
		s.apply(item.id, item.events)
	}
}

type stateSimOut struct {
	id     PeerID
	events []OutEvent
}

// sortedPeers returns the keys of m in a fixed order. The simulation seeds
// each node, so ranging over a map is the one thing that makes a round
// nondeterministic: the order nodes act in decides the overlay they converge
// to, and an unlucky order left a node unreachable about once in a hundred
// runs.
func sortedPeers[V any](m map[PeerID]V) []PeerID {
	ids := make([]PeerID, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b PeerID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

func (s *stateSim) broadcast(origin int, content []byte) {
	id := s.peer(origin)
	node := s.nodes[id]
	if node == nil {
		return
	}
	s.delivered[id] = append(s.delivered[id], TopicEvent{
		Kind:    TopicReceived,
		Content: append([]byte(nil), content...),
		Scope:   DeliveryScope{Kind: DeliveryScopeSwarm},
	})
	s.apply(id, node.Handle(InEvent{
		Kind:  CommandEvent,
		Topic: s.topic,
		Command: TopicCommand{
			Kind:    TopicCommandBroadcast,
			Content: content,
			Scope:   ScopeSwarm,
		},
		Now: s.now,
	}))
}

func (s *stateSim) runRounds(n int) {
	for range n {
		s.drainMessages()
		s.fireTimers()
		s.now = s.now.Add(time.Second)
	}
	s.drainMessages()
}

func (s *stateSim) drainMessages() {
	for i := 0; len(s.queue) > 0 && i < 1000; i++ {
		msg := s.queue[0]
		s.queue = s.queue[1:]
		node := s.nodes[msg.to]
		if node == nil {
			continue
		}
		s.apply(msg.to, node.Handle(InEvent{
			Kind:    RecvMessage,
			From:    msg.from,
			Message: msg.message,
			Now:     s.now,
		}))
	}
}

func (s *stateSim) fireTimers() {
	pending := s.timers
	s.timers = make(map[PeerID][]Timer)
	for _, id := range sortedPeers(pending) {
		node := s.nodes[id]
		if node == nil {
			continue
		}
		for _, timer := range pending[id] {
			s.apply(id, node.Handle(InEvent{
				Kind:  TimerExpired,
				Timer: timer,
				Now:   s.now,
			}))
		}
	}
}

func (s *stateSim) apply(from PeerID, events []OutEvent) {
	for _, ev := range events {
		switch ev.Kind {
		case SendMessage:
			if s.nodes[ev.To] == nil {
				continue
			}
			s.queue = append(s.queue, stateSimMessage{from: from, to: ev.To, message: ev.Message})
		case ScheduleTimer:
			s.timers[from] = append(s.timers[from], ev.Timer)
		case DisconnectPeer:
			node := s.nodes[from]
			if node != nil {
				s.apply(from, node.Handle(InEvent{Kind: PeerDisconnected, Peer: ev.To, Now: s.now}))
			}
		case EmitEvent:
			if ev.Event.Kind == TopicReceived {
				s.delivered[from] = append(s.delivered[from], ev.Event)
			}
		}
	}
}

func (s *stateSim) requireOverlay(t *testing.T, name string) {
	t.Helper()
	for _, id := range sortedPeers(s.nodes) {
		node := s.nodes[id]
		topic := node.topics[s.topic]
		if topic == nil {
			t.Fatalf("%s: %x has no topic", name, id)
		}
		active := topic.swarm.ActivePeers()
		if len(active) == 0 {
			t.Fatalf("%s: %x has no active neighbors", name, id)
		}
		if len(active) > s.config.Topic.Membership.ActiveViewCapacity {
			t.Fatalf("%s: %x active view = %d, want <= %d", name, id, len(active), s.config.Topic.Membership.ActiveViewCapacity)
		}
	}
}

func (s *stateSim) requireBroadcast(t *testing.T, origin int, content []byte, maxHop Round) {
	t.Helper()
	originID := s.peer(origin)
	for _, id := range sortedPeers(s.nodes) {
		var found bool
		var hop Round
		for _, ev := range s.delivered[id] {
			if !bytes.Equal(ev.Content, content) {
				continue
			}
			found = true
			hop = ev.Scope.Round
			break
		}
		if !found {
			t.Fatalf("%x did not receive broadcast from %x", id, originID)
		}
		if hop > maxHop {
			t.Fatalf("%x last delivery hop = %d, want <= %d", id, hop, maxHop)
		}
	}
}
