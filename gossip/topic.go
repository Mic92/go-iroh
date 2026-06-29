package gossip

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

const defaultTopicEventCap = 256

// EventKind identifies a topic event.
type EventKind uint8

const (
	// NeighborUp reports a new direct neighbor for the topic.
	NeighborUp EventKind = iota
	// NeighborDown reports a dropped direct neighbor for the topic.
	NeighborDown
	// Received reports an application gossip message.
	Received
	// Lagged reports that a slow receiver missed one or more events.
	Lagged
)

// DeliveryScope identifies how a received message was delivered.
type DeliveryScope uint8

const (
	// DeliverySwarm reports an epidemic overlay delivery.
	DeliverySwarm DeliveryScope = iota
	// DeliveryNeighbors reports a direct-neighbor delivery.
	DeliveryNeighbors
)

// Event is emitted by a subscribed gossip topic.
type Event struct {
	Kind          EventKind
	Peer          key.EndpointID
	Content       []byte
	DeliveredFrom key.EndpointID
	Scope         DeliveryScope
	// Round is the PlumTree delivery round for DeliverySwarm messages.
	// It is zero for direct-neighbor delivery.
	Round uint16
}

// GossipOption configures a Gossip instance.
type GossipOption func(*Gossip)

// WithMaxMessageSize sets the maximum postcard frame body size. Non-positive
// values use the Rust default.
func WithMaxMessageSize(n int) GossipOption {
	return func(g *Gossip) {
		if n > 0 {
			g.maxMessageSize = gossipproto.NormalizeMaxMessageSize(n)
		}
	}
}

// Gossip publishes and subscribes to iroh-gossip topics.
//
// Register [Gossip.Handler] with an iroh Router under [ALPN].
type Gossip struct {
	ep             *iroh.Endpoint
	maxMessageSize int

	mu          sync.Mutex
	state       *gossipproto.State
	topics      map[TopicID]map[*Topic]struct{}
	neighbors   map[TopicID]map[PeerID]struct{}
	peerAddrs   map[PeerID]netaddr.EndpointAddr
	peerSenders map[PeerID]*Sender
	closed      bool
}

// NewGossip returns a Gossip instance for ep.
func NewGossip(ep *iroh.Endpoint, opts ...GossipOption) *Gossip {
	g := &Gossip{
		ep:             ep,
		maxMessageSize: gossipproto.DefaultMaxMessageSize,
		topics:         make(map[TopicID]map[*Topic]struct{}),
		neighbors:      make(map[TopicID]map[PeerID]struct{}),
		peerAddrs:      make(map[PeerID]netaddr.EndpointAddr),
		peerSenders:    make(map[PeerID]*Sender),
	}
	for _, opt := range opts {
		opt(g)
	}
	if ep != nil {
		config := gossipproto.DefaultConfig()
		config.MaxMessageSize = g.maxMessageSize
		g.state = gossipproto.NewState(peerIDFromEndpoint(ep.ID()), nil, config)
	}
	return g
}

// Handler returns the protocol handler for registering this Gossip with an
// iroh Router.
func (g *Gossip) Handler() iroh.ProtocolHandler { return g }

// Shutdown closes topic subscriptions and open topic send streams.
func (g *Gossip) Shutdown(ctx context.Context) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	var out []gossipproto.OutEvent
	now := time.Now()
	for topic, subs := range g.topics {
		out = append(out, g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.CommandEvent,
			Topic: topic,
			Command: gossipproto.TopicCommand{
				Kind: gossipproto.TopicCommandQuit,
			},
			Now: now,
		})...)
		for t := range subs {
			t.closeEvents()
		}
	}
	g.topics = make(map[TopicID]map[*Topic]struct{})
	senders := make([]*Sender, 0, len(g.peerSenders))
	for peer, sender := range g.peerSenders {
		delete(g.peerSenders, peer)
		senders = append(senders, sender)
	}
	g.mu.Unlock()
	g.dispatch(ctx, out)
	for _, sender := range senders {
		_ = sender.Close()
	}
}

// Accept handles one incoming iroh-gossip connection.
func (g *Gossip) Accept(ctx context.Context, conn *iroh.Conn) error {
	if g == nil {
		return errors.New("gossip: nil Gossip")
	}
	from := peerIDFromEndpoint(conn.RemoteID())
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errors.New("gossip: closed")
	}
	sender := NewSender(conn, g.maxMessageSize)
	g.peerSenders[from] = sender
	g.mu.Unlock()

	h := Handler{
		MaxMessageSize: g.maxMessageSize,
		Handle: func(ctx context.Context, from key.EndpointID, msg Message) error {
			return g.receive(ctx, from, msg)
		},
	}
	err := h.Accept(ctx, conn)
	g.mu.Lock()
	if g.peerSenders[from] == sender {
		delete(g.peerSenders, from)
	}
	out := g.handleLocked(gossipproto.InEvent{
		Kind: gossipproto.PeerDisconnected,
		Peer: from,
		Now:  time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return err
}

// Subscribe joins topic and returns a local handle for publishing and receiving
// events. Bootstrap peers are dialed as needed.
func (g *Gossip) Subscribe(ctx context.Context, topic TopicID, bootstrap []netaddr.EndpointAddr) (*Topic, error) {
	if g == nil || g.ep == nil || g.state == nil {
		return nil, errors.New("gossip: nil Gossip")
	}
	t := &Topic{
		g:      g,
		id:     topic,
		events: make(chan Event, defaultTopicEventCap),
	}
	peers := make([]PeerID, 0, len(bootstrap))
	for _, addr := range bootstrap {
		if addr.ID.IsZero() {
			continue
		}
		peer := peerIDFromEndpoint(addr.ID)
		peers = append(peers, peer)
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, errors.New("gossip: closed")
	}
	for _, addr := range bootstrap {
		if addr.ID.IsZero() {
			continue
		}
		g.peerAddrs[peerIDFromEndpoint(addr.ID)] = addr
	}
	if g.topics[topic] == nil {
		g.topics[topic] = make(map[*Topic]struct{})
	}
	g.topics[topic][t] = struct{}{}
	out := g.handleLocked(gossipproto.InEvent{
		Kind:  gossipproto.CommandEvent,
		Topic: topic,
		Command: gossipproto.TopicCommand{
			Kind:  gossipproto.TopicCommandJoin,
			Peers: peers,
		},
		Now: time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return t, nil
}

func (g *Gossip) receive(ctx context.Context, from key.EndpointID, msg Message) error {
	g.mu.Lock()
	out := g.handleLocked(gossipproto.InEvent{
		Kind:    gossipproto.RecvMessage,
		From:    peerIDFromEndpoint(from),
		Message: gossipproto.Message(msg),
		Now:     time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return nil
}

func (g *Gossip) command(ctx context.Context, topic TopicID, cmd gossipproto.TopicCommand) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errors.New("gossip: closed")
	}
	out := g.handleLocked(gossipproto.InEvent{
		Kind:    gossipproto.CommandEvent,
		Topic:   topic,
		Command: cmd,
		Now:     time.Now(),
	})
	g.mu.Unlock()
	g.dispatch(ctx, out)
	return nil
}

func (g *Gossip) closeTopic(t *Topic) error {
	g.mu.Lock()
	if t.closed {
		g.mu.Unlock()
		return nil
	}
	t.closeEvents()
	delete(g.topics[t.id], t)
	empty := len(g.topics[t.id]) == 0
	if empty {
		delete(g.topics, t.id)
	}
	var out []gossipproto.OutEvent
	if empty && !g.closed {
		out = g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.CommandEvent,
			Topic: t.id,
			Command: gossipproto.TopicCommand{
				Kind: gossipproto.TopicCommandQuit,
			},
			Now: time.Now(),
		})
	}
	g.mu.Unlock()
	g.dispatch(context.Background(), out)
	return nil
}

func (g *Gossip) handleLocked(in gossipproto.InEvent) []gossipproto.OutEvent {
	if g.state == nil {
		return nil
	}
	return g.state.Handle(in)
}

func (g *Gossip) dispatch(ctx context.Context, events []gossipproto.OutEvent) {
	for _, ev := range events {
		switch ev.Kind {
		case gossipproto.SendMessage:
			if err := g.send(ctx, ev.To, ev.Message); err != nil {
				g.mu.Lock()
				out := g.handleLocked(gossipproto.InEvent{
					Kind: gossipproto.PeerDisconnected,
					Peer: ev.To,
					Now:  time.Now(),
				})
				g.mu.Unlock()
				if len(out) > 0 {
					g.dispatch(ctx, out)
				}
			}
		case gossipproto.EmitEvent:
			g.emit(ev.Topic, ev.Event)
		case gossipproto.ScheduleTimer:
			g.schedule(ev.After, ev.Timer)
		case gossipproto.DisconnectPeer:
			g.disconnect(ev.To)
		}
	}
}

func (g *Gossip) send(ctx context.Context, peer PeerID, msg gossipproto.Message) error {
	g.mu.Lock()
	sender := g.peerSenders[peer]
	addr, hasAddr := g.peerAddrs[peer]
	g.mu.Unlock()
	if sender == nil {
		if !hasAddr {
			return fmt.Errorf("gossip: no address for peer %s", peer)
		}
		if err := g.connect(ctx, peer, addr); err != nil {
			return err
		}
		g.mu.Lock()
		sender = g.peerSenders[peer]
		g.mu.Unlock()
	}
	if sender == nil {
		return fmt.Errorf("gossip: no sender for peer %s", peer)
	}
	return sender.Send(ctx, Message(msg))
}

func (g *Gossip) connect(ctx context.Context, peer PeerID, addr netaddr.EndpointAddr) error {
	conn, err := g.ep.Connect(ctx, addr, ALPN)
	if err != nil {
		return fmt.Errorf("gossip: connect peer: %w", err)
	}
	g.mu.Lock()
	g.peerSenders[peer] = NewSender(conn, g.maxMessageSize)
	g.mu.Unlock()
	go func() {
		_ = g.Accept(conn.Context(), conn)
	}()
	return nil
}

func (g *Gossip) emit(topic TopicID, ev gossipproto.TopicEvent) {
	event, ok := publicEvent(ev)
	if !ok {
		return
	}
	g.mu.Lock()
	if ev.Kind == gossipproto.TopicNeighborUp {
		if g.neighbors[topic] == nil {
			g.neighbors[topic] = make(map[PeerID]struct{})
		}
		g.neighbors[topic][ev.Peer] = struct{}{}
	} else if ev.Kind == gossipproto.TopicNeighborDown {
		delete(g.neighbors[topic], ev.Peer)
	}
	subs := make([]*Topic, 0, len(g.topics[topic]))
	for t := range g.topics[topic] {
		subs = append(subs, t)
	}
	g.mu.Unlock()
	for _, t := range subs {
		t.sendEvent(event)
	}
}

func (g *Gossip) schedule(after time.Duration, timer gossipproto.Timer) {
	if after < 0 {
		after = 0
	}
	time.AfterFunc(after, func() {
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			return
		}
		out := g.handleLocked(gossipproto.InEvent{
			Kind:  gossipproto.TimerExpired,
			Timer: timer,
			Now:   time.Now(),
		})
		g.mu.Unlock()
		g.dispatch(context.Background(), out)
	})
}

func (g *Gossip) disconnect(peer PeerID) {
	g.mu.Lock()
	sender := g.peerSenders[peer]
	delete(g.peerSenders, peer)
	g.mu.Unlock()
	if sender != nil {
		_ = sender.Close()
	}
}

// Topic is a local subscription to one gossip topic.
type Topic struct {
	g      *Gossip
	id     TopicID
	events chan Event

	mu     sync.Mutex
	closed bool
}

// ID returns the topic ID.
func (t *Topic) ID() TopicID { return t.id }

// Broadcast sends content to the topic's epidemic overlay.
func (t *Topic) Broadcast(ctx context.Context, content []byte) error {
	if t.isClosed() {
		return errors.New("gossip: topic closed")
	}
	return t.g.command(ctx, t.id, gossipproto.TopicCommand{
		Kind:    gossipproto.TopicCommandBroadcast,
		Content: append([]byte(nil), content...),
		Scope:   gossipproto.ScopeSwarm,
	})
}

// BroadcastNeighbors sends content to the topic's direct neighbors.
func (t *Topic) BroadcastNeighbors(ctx context.Context, content []byte) error {
	if t.isClosed() {
		return errors.New("gossip: topic closed")
	}
	return t.g.command(ctx, t.id, gossipproto.TopicCommand{
		Kind:    gossipproto.TopicCommandBroadcast,
		Content: append([]byte(nil), content...),
		Scope:   gossipproto.ScopeNeighbors,
	})
}

// JoinPeers dials and joins additional peers for this topic.
func (t *Topic) JoinPeers(ctx context.Context, peers []netaddr.EndpointAddr) error {
	if t.isClosed() {
		return errors.New("gossip: topic closed")
	}
	ids := make([]PeerID, 0, len(peers))
	t.g.mu.Lock()
	for _, addr := range peers {
		if addr.ID.IsZero() {
			continue
		}
		peer := peerIDFromEndpoint(addr.ID)
		ids = append(ids, peer)
		t.g.peerAddrs[peer] = addr
	}
	t.g.mu.Unlock()
	return t.g.command(ctx, t.id, gossipproto.TopicCommand{
		Kind:  gossipproto.TopicCommandJoin,
		Peers: ids,
	})
}

// Events returns the topic event stream.
func (t *Topic) Events() iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		for ev := range t.events {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// Close leaves the topic when this is its last local subscription.
func (t *Topic) Close() error { return t.g.closeTopic(t) }

func (t *Topic) sendEvent(ev Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	select {
	case t.events <- ev:
	default:
		select {
		case t.events <- Event{Kind: Lagged}:
		default:
		}
	}
}

func (t *Topic) closeEvents() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.closed = true
	close(t.events)
}

func (t *Topic) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func publicEvent(ev gossipproto.TopicEvent) (Event, bool) {
	switch ev.Kind {
	case gossipproto.TopicNeighborUp:
		id, err := endpointFromPeerID(ev.Peer)
		if err != nil {
			return Event{}, false
		}
		return Event{Kind: NeighborUp, Peer: id}, true
	case gossipproto.TopicNeighborDown:
		id, err := endpointFromPeerID(ev.Peer)
		if err != nil {
			return Event{}, false
		}
		return Event{Kind: NeighborDown, Peer: id}, true
	case gossipproto.TopicReceived:
		from, err := endpointFromPeerID(ev.DeliveredFrom)
		if err != nil {
			return Event{}, false
		}
		return Event{
			Kind:          Received,
			Content:       append([]byte(nil), ev.Content...),
			DeliveredFrom: from,
			Scope:         publicScope(ev.Scope),
			Round:         uint16(ev.Scope.Round),
		}, true
	default:
		return Event{}, false
	}
}

func publicScope(scope gossipproto.DeliveryScope) DeliveryScope {
	if scope.Kind == gossipproto.DeliveryScopeNeighbors {
		return DeliveryNeighbors
	}
	return DeliverySwarm
}

func peerIDFromEndpoint(id key.EndpointID) PeerID {
	return PeerID(id.Bytes())
}

func endpointFromPeerID(id PeerID) (key.EndpointID, error) {
	return key.NewEndpointID([32]byte(id))
}
