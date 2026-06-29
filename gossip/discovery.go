package gossip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"lukechampine.com/blake3"
)

const (
	// Provenance is the provenance reported on resolved gossip discovery items.
	Provenance = "gossip"

	defaultDiscoveryTimeout = 10 * time.Second
)

// DefaultDiscoveryTopic is the default topic used by Discovery.
var DefaultDiscoveryTopic = TopicID(blake3.Sum256([]byte("iroh-gossip-discovery-v1")))

// Option configures a Discovery.
type Option func(*Discovery)

// WithGossip configures the gossip overlay used by a Discovery.
func WithGossip(g *Gossip, topic TopicID, bootstrap []netaddr.EndpointAddr) Option {
	return func(d *Discovery) {
		d.gossip = g
		d.topicID = topic
		d.bootstrap = append([]netaddr.EndpointAddr(nil), bootstrap...)
	}
}

// WithLookupTimeout sets how long Resolve waits after a cache miss.
func WithLookupTimeout(timeout time.Duration) Option {
	return func(d *Discovery) {
		if timeout > 0 {
			d.timeout = timeout
		}
	}
}

// Discovery publishes and resolves endpoint addressing information over a
// gossip topic. The zero value is not usable; create one with [New].
type Discovery struct {
	id        key.EndpointID
	gossip    *Gossip
	topicID   TopicID
	bootstrap []netaddr.EndpointAddr
	timeout   time.Duration

	mu      sync.Mutex
	peers   map[key.EndpointID]discoveryPeer
	topic   *Topic
	pending *dns.EndpointData
}

type discoveryPeer struct {
	data        dns.EndpointData
	lastUpdated uint64
}

type discoveryMessage struct {
	ID       string   `json:"id"`
	Addrs    []string `json:"addrs,omitempty"`
	UserData *string  `json:"user_data,omitempty"`
}

// New returns a Discovery for id.
func New(id key.EndpointID, opts ...Option) *Discovery {
	d := &Discovery{
		id:      id,
		topicID: DefaultDiscoveryTopic,
		timeout: defaultDiscoveryTimeout,
		peers:   make(map[key.EndpointID]discoveryPeer),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Start subscribes to the configured gossip topic until ctx is cancelled.
func (d *Discovery) Start(ctx context.Context) error {
	if d == nil {
		return errors.New("gossip: nil Discovery")
	}
	if d.gossip == nil {
		<-ctx.Done()
		return nil
	}
	topic, err := d.gossip.Subscribe(ctx, d.topicID, d.bootstrap)
	if err != nil {
		return fmt.Errorf("gossip: discovery subscribe: %w", err)
	}
	d.mu.Lock()
	d.topic = topic
	pending := cloneEndpointDataPtr(d.pending)
	d.mu.Unlock()
	if pending != nil {
		d.broadcast(*pending)
	}
	go func() {
		<-ctx.Done()
		_ = topic.Close()
	}()
	for ev, err := range topic.Events() {
		if err != nil {
			return err
		}
		if ev.Kind != Received {
			continue
		}
		if err := d.handleMessage(ev.Content); err != nil {
			continue
		}
	}
	return nil
}

// Publish advertises data on the gossip topic. It is fire-and-forget and
// returns immediately, matching iroh.AddressPublisher.
func (d *Discovery) Publish(data dns.EndpointData) {
	if d == nil {
		return
	}
	d.mu.Lock()
	d.pending = &data
	d.peers[d.id] = discoveryPeer{
		data:        cloneEndpointData(data),
		lastUpdated: uint64(time.Now().UnixMicro()),
	}
	topic := d.topic
	d.mu.Unlock()
	if topic != nil {
		d.broadcast(data)
	}
}

// Resolve returns the cached item for id, if present, and otherwise waits until
// ctx or the lookup timeout fires.
func (d *Discovery) Resolve(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
	if d == nil {
		return nil
	}
	return func(yield func(iroh.Item, error) bool) {
		if item, ok := d.item(id); ok {
			yield(item, nil)
			return
		}
		timer := time.NewTimer(d.timeout)
		defer timer.Stop()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				yield(iroh.Item{}, ctx.Err())
				return
			case <-timer.C:
				return
			case <-tick.C:
				if item, ok := d.item(id); ok {
					yield(item, nil)
					return
				}
			}
		}
	}
}

func (d *Discovery) broadcast(data dns.EndpointData) {
	b, err := encodeDiscoveryMessage(d.id, data)
	if err != nil {
		return
	}
	d.mu.Lock()
	topic := d.topic
	d.mu.Unlock()
	if topic == nil {
		return
	}
	go func() { _ = topic.Broadcast(context.Background(), b) }()
}

func (d *Discovery) handleMessage(b []byte) error {
	id, data, err := decodeDiscoveryMessage(b)
	if err != nil {
		return err
	}
	if id.Equal(d.id) {
		return nil
	}
	d.mu.Lock()
	d.peers[id] = discoveryPeer{
		data:        cloneEndpointData(data),
		lastUpdated: uint64(time.Now().UnixMicro()),
	}
	d.mu.Unlock()
	return nil
}

func (d *Discovery) item(id key.EndpointID) (iroh.Item, bool) {
	d.mu.Lock()
	peer, ok := d.peers[id]
	d.mu.Unlock()
	if !ok {
		return iroh.Item{}, false
	}
	info := dns.EndpointInfo{ID: id, Data: cloneEndpointData(peer.data)}
	return iroh.NewItem(info, Provenance, &peer.lastUpdated), true
}

func encodeDiscoveryMessage(id key.EndpointID, data dns.EndpointData) ([]byte, error) {
	msg := discoveryMessage{ID: id.String()}
	for _, addr := range data.Addrs() {
		msg.Addrs = append(msg.Addrs, addr.String())
	}
	if u := data.UserData(); u != nil {
		s := u.String()
		msg.UserData = &s
	}
	return json.Marshal(msg)
}

func decodeDiscoveryMessage(b []byte) (key.EndpointID, dns.EndpointData, error) {
	var msg discoveryMessage
	if err := json.Unmarshal(b, &msg); err != nil {
		return key.EndpointID{}, dns.EndpointData{}, fmt.Errorf("gossip: decode discovery message: %w", err)
	}
	id, err := key.ParseEndpointID(msg.ID)
	if err != nil {
		return key.EndpointID{}, dns.EndpointData{}, fmt.Errorf("gossip: decode discovery id: %w", err)
	}
	var addrs []netaddr.TransportAddr
	for _, s := range msg.Addrs {
		addr, err := netaddr.ParseTransportAddr(s)
		if err != nil {
			return key.EndpointID{}, dns.EndpointData{}, fmt.Errorf("gossip: decode discovery addr: %w", err)
		}
		addrs = append(addrs, addr)
	}
	data := dns.NewEndpointData(addrs...)
	if msg.UserData != nil {
		u, err := dns.NewUserData(*msg.UserData)
		if err != nil {
			return key.EndpointID{}, dns.EndpointData{}, fmt.Errorf("gossip: decode discovery user data: %w", err)
		}
		data = data.WithUserData(&u)
	}
	return id, data, nil
}

func cloneEndpointDataPtr(data *dns.EndpointData) *dns.EndpointData {
	if data == nil {
		return nil
	}
	clone := cloneEndpointData(*data)
	return &clone
}

func cloneEndpointData(data dns.EndpointData) dns.EndpointData {
	clone := dns.NewEndpointData(data.Addrs()...)
	if u := data.UserData(); u != nil {
		uc := *u
		clone = clone.WithUserData(&uc)
	}
	return clone
}
