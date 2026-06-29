package docs

import (
	"context"
	"errors"
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// LiveSyncOptions configures live document synchronization over iroh-gossip.
type LiveSyncOptions struct {
	// Bootstrap is the initial set of peers to join and sync with.
	Bootstrap []netaddr.EndpointAddr
	// Resolver resolves neighbor IDs to endpoint addresses before syncing.
	Resolver iroh.AddressResolver
	// BlobStore reports which entry content is locally available.
	BlobStore blobs.Store
	// Config configures range reconciliation.
	Config SyncConfig
	// OnSync, if non-nil, is called after each sync attempt.
	OnSync func(SyncResult)
}

type liveSyncOptions struct {
	LiveSyncOptions
	syncPeer func(context.Context, netaddr.EndpointAddr) (SyncOutcome, error)
}

// LiveSync keeps a document store synchronized over an iroh-gossip topic.
type LiveSync struct {
	cancel      context.CancelFunc
	done        chan struct{}
	topic       *gossip.Topic
	cancelStore func()
}

// StartLiveSync starts live synchronization for namespace.
//
// Local store inserts are broadcast over gossip. Received inserts are added as
// remote entries. New neighbors and bootstrap peers are synchronized with the
// iroh-docs range-reconciliation protocol.
func StartLiveSync(ctx context.Context, ep *iroh.Endpoint, g *gossip.Gossip, namespace NamespaceID, store *MemoryStore, opts LiveSyncOptions) (*LiveSync, error) {
	if ep == nil {
		return nil, errors.New("docs: nil endpoint")
	}
	if g == nil {
		return nil, errors.New("docs: nil gossip")
	}
	if store == nil {
		return nil, errors.New("docs: nil store")
	}
	topic, err := g.Subscribe(ctx, gossip.TopicID(namespace.Bytes()), opts.Bootstrap)
	if err != nil {
		return nil, fmt.Errorf("docs: subscribe gossip: %w", err)
	}
	cfg := liveSyncOptions{LiveSyncOptions: opts}
	cfg.syncPeer = func(ctx context.Context, addr netaddr.EndpointAddr) (SyncOutcome, error) {
		return Sync(ctx, ep, addr, namespace, store, opts.BlobStore, opts.Config)
	}
	ctx, cancel := context.WithCancel(ctx)
	events, cancelStore := store.Subscribe()
	l := &LiveSync{
		cancel:      cancel,
		done:        make(chan struct{}),
		topic:       topic,
		cancelStore: cancelStore,
	}
	go l.run(ctx, namespace, store, cfg, events)
	return l, nil
}

// Close stops the live synchronization background task.
func (l *LiveSync) Close() error {
	if l == nil {
		return nil
	}
	l.cancel()
	if l.cancelStore != nil {
		l.cancelStore()
	}
	err := l.topic.Close()
	<-l.done
	return err
}

func (l *LiveSync) run(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, storeEvents <-chan StoreEvent) {
	defer close(l.done)
	topicEvents := make(chan gossip.Event)
	go func() {
		defer close(topicEvents)
		for ev, err := range l.topic.Events() {
			if err != nil {
				continue
			}
			select {
			case topicEvents <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	if len(opts.Bootstrap) != 0 {
		go l.syncPeers(ctx, opts, opts.Bootstrap)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-storeEvents:
			if !ok {
				return
			}
			l.handleStoreEvent(ctx, ev)
		case ev, ok := <-topicEvents:
			if !ok {
				return
			}
			l.handleTopicEvent(ctx, namespace, store, opts, ev)
		}
	}
}

func (l *LiveSync) handleStoreEvent(ctx context.Context, ev StoreEvent) {
	if ev.Kind != StoreEventInsertLocal {
		return
	}
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: ev.Entry})
	if err != nil {
		return
	}
	_ = l.topic.Broadcast(ctx, msg)
}

func (l *LiveSync) handleTopicEvent(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, ev gossip.Event) {
	switch ev.Kind {
	case gossip.Received:
		l.handleReceived(ctx, namespace, store, opts, ev)
	case gossip.NeighborUp:
		addr, ok := l.resolvePeer(ctx, opts.Resolver, ev.Peer)
		if !ok {
			addr = netaddr.EndpointAddr{ID: ev.Peer}
		}
		go l.syncPeers(ctx, opts, []netaddr.EndpointAddr{addr})
	case gossip.Lagged:
		// A missed gossip event means we may have missed a Put. Sync known peers.
		go l.syncPeers(ctx, opts, opts.Bootstrap)
	}
}

func (l *LiveSync) handleReceived(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, ev gossip.Event) {
	var op liveOp
	if err := postcard.Unmarshal(ev.Content, &op); err != nil {
		return
	}
	switch op.Kind {
	case liveOpPut:
		if op.Entry.Entry.Namespace() != namespace || op.Entry.Verify() != nil {
			return
		}
		status := ContentMissing
		if ev.Scope == gossip.DeliveryNeighbors || (ev.Scope == gossip.DeliverySwarm && ev.Round == 0) {
			status = ContentComplete
		}
		store.PutWithOrigin(op.Entry, InsertOrigin{
			Kind:          InsertOriginRemote,
			From:          ev.DeliveredFrom,
			ContentStatus: status,
		})
	case liveOpSyncReport:
		if op.Report.Namespace != namespace {
			return
		}
		addr, ok := l.resolvePeer(ctx, opts.Resolver, ev.DeliveredFrom)
		if !ok {
			addr = netaddr.EndpointAddr{ID: ev.DeliveredFrom}
		}
		go l.syncPeers(ctx, opts, []netaddr.EndpointAddr{addr})
	}
}

func (l *LiveSync) syncPeers(ctx context.Context, opts liveSyncOptions, peers []netaddr.EndpointAddr) {
	for _, peer := range peers {
		var outcome SyncOutcome
		var err error
		if opts.syncPeer != nil {
			outcome, err = opts.syncPeer(ctx, peer)
		} else {
			err = errors.New("docs: sync peer not configured")
		}
		if opts.OnSync != nil {
			opts.OnSync(SyncResult{Addr: peer, Outcome: outcome, Err: err})
		}
	}
}

func (l *LiveSync) resolvePeer(ctx context.Context, resolver iroh.AddressResolver, id key.EndpointID) (netaddr.EndpointAddr, bool) {
	if resolver == nil || id.IsZero() {
		return netaddr.EndpointAddr{}, false
	}
	for item, err := range resolver.Resolve(ctx, id) {
		if err != nil {
			continue
		}
		return item.Addr(), true
	}
	return netaddr.EndpointAddr{}, false
}

type liveOpKind uint64

const (
	liveOpPut liveOpKind = iota
	liveOpContentReady
	liveOpSyncReport
)

type liveOp struct {
	Kind   liveOpKind
	Entry  SignedEntry
	Hash   blobs.Hash
	Report liveSyncReport
}

type liveSyncReport struct {
	Namespace NamespaceID
	Heads     []byte
}

func (op liveOp) EncodePostcard(e *postcard.Encoder) error {
	e.Uint(uint64(op.Kind))
	switch op.Kind {
	case liveOpPut:
		return e.Encode(op.Entry)
	case liveOpContentReady:
		e.RawBytes(op.Hash[:])
		return nil
	case liveOpSyncReport:
		return e.Encode(op.Report)
	default:
		return fmt.Errorf("docs: unknown live op %d", op.Kind)
	}
}

func (op *liveOp) DecodePostcard(d *postcard.Decoder) error {
	kind, err := d.Uint()
	if err != nil {
		return err
	}
	op.Kind = liveOpKind(kind)
	switch op.Kind {
	case liveOpPut:
		return d.Decode(&op.Entry)
	case liveOpContentReady:
		b, err := d.RawBytes(len(op.Hash))
		if err != nil {
			return err
		}
		copy(op.Hash[:], b)
		return nil
	case liveOpSyncReport:
		return d.Decode(&op.Report)
	default:
		return fmt.Errorf("docs: unknown live op %d", op.Kind)
	}
}

func (r liveSyncReport) EncodePostcard(e *postcard.Encoder) error {
	if err := e.Encode(r.Namespace); err != nil {
		return err
	}
	e.BytesValue(r.Heads)
	return nil
}

func (r *liveSyncReport) DecodePostcard(d *postcard.Decoder) error {
	if err := d.Decode(&r.Namespace); err != nil {
		return err
	}
	heads, err := d.BytesValue()
	if err != nil {
		return err
	}
	r.Heads = heads
	return nil
}
