package docs

import (
	"context"
	"errors"
	"fmt"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
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
	syncPeer             func(context.Context, netaddr.EndpointAddr) (SyncOutcome, error)
	downloadBlob         func(context.Context, netaddr.EndpointAddr, blobs.Hash) error
	maxGossipPayloadSize int
}

const liveDownloadQueueSize = 16

// LiveSync keeps a document store synchronized over an iroh-gossip topic.
type LiveSync struct {
	cancel      context.CancelFunc
	done        chan struct{}
	topic       *gossip.Topic
	cancelStore func()
	downloads   chan liveDownload
	pending     map[blobs.Hash]struct{}
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
	cfg.maxGossipPayloadSize = gossipproto.MaxPayloadSize(g.MaxMessageSize())
	cfg.syncPeer = func(ctx context.Context, addr netaddr.EndpointAddr) (SyncOutcome, error) {
		return Sync(ctx, ep, addr, namespace, store, opts.BlobStore, opts.Config)
	}
	cfg.downloadBlob = func(ctx context.Context, addr netaddr.EndpointAddr, hash blobs.Hash) error {
		return downloadBlob(ctx, ep, addr, opts.BlobStore, hash)
	}
	ctx, cancel := context.WithCancel(ctx)
	events, cancelStore := store.Subscribe()
	l := &LiveSync{
		cancel:      cancel,
		done:        make(chan struct{}),
		topic:       topic,
		cancelStore: cancelStore,
		downloads:   make(chan liveDownload, liveDownloadQueueSize),
		pending:     make(map[blobs.Hash]struct{}),
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
		go l.syncPeers(ctx, namespace, store, opts, opts.Bootstrap)
	}
	go l.runDownloader(ctx, store, opts)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-storeEvents:
			if !ok {
				return
			}
			l.handleStoreEvent(ctx, opts, ev)
		case ev, ok := <-topicEvents:
			if !ok {
				return
			}
			l.handleTopicEvent(ctx, namespace, store, opts, ev)
		}
	}
}

func (l *LiveSync) handleStoreEvent(ctx context.Context, opts liveSyncOptions, ev StoreEvent) {
	if ev.Kind != StoreEventInsertLocal {
		return
	}
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: ev.Entry})
	if err != nil {
		return
	}
	_ = l.topic.Broadcast(ctx, msg)
	hash := ev.Entry.Entry.ContentHash()
	if blobs.Status(opts.BlobStore, hash).IsComplete() {
		l.broadcastContentReady(ctx, hash)
	}
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
		go l.syncPeers(ctx, namespace, store, opts, []netaddr.EndpointAddr{addr})
	case gossip.Lagged:
		// A missed gossip event means we may have missed a Put. Sync known peers.
		go l.syncPeers(ctx, namespace, store, opts, opts.Bootstrap)
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
		hash := op.Entry.Entry.ContentHash()
		status := ContentMissing
		if blobs.Status(opts.BlobStore, hash).IsComplete() {
			status = ContentComplete
		}
		outcome := store.PutWithOrigin(op.Entry, InsertOrigin{
			Kind:          InsertOriginRemote,
			From:          ev.DeliveredFrom,
			ContentStatus: status,
		})
		if outcome.Inserted() && status != ContentComplete {
			l.queueDownload(ctx, opts, hash, ev.DeliveredFrom)
		}
	case liveOpContentReady:
		if op.Hash != blobs.EmptyHash {
			l.queueDownload(ctx, opts, op.Hash, ev.DeliveredFrom)
		}
	case liveOpSyncReport:
		if op.Report.Namespace != namespace {
			return
		}
		if !store.hasNewsForUs(namespace, op.Report.Heads) {
			return
		}
		addr, ok := l.resolvePeer(ctx, opts.Resolver, ev.DeliveredFrom)
		if !ok {
			addr = netaddr.EndpointAddr{ID: ev.DeliveredFrom}
		}
		go l.syncPeers(ctx, namespace, store, opts, []netaddr.EndpointAddr{addr})
	}
}

func (l *LiveSync) broadcastContentReady(ctx context.Context, hash blobs.Hash) {
	msg, err := postcard.Marshal(liveOp{Kind: liveOpContentReady, Hash: hash})
	if err != nil {
		return
	}
	_ = l.topic.Broadcast(ctx, msg)
}

func (l *LiveSync) queueDownload(ctx context.Context, opts liveSyncOptions, hash blobs.Hash, peer key.EndpointID) {
	if l.downloads == nil || hash == blobs.EmptyHash || blobs.Status(opts.BlobStore, hash).IsComplete() {
		return
	}
	addr, ok := l.downloadAddr(ctx, opts, peer)
	if !ok {
		return
	}
	if l.pending == nil {
		l.pending = make(map[blobs.Hash]struct{})
	}
	if _, ok := l.pending[hash]; ok {
		return
	}
	l.pending[hash] = struct{}{}
	select {
	case l.downloads <- liveDownload{Hash: hash, Addr: addr}:
	case <-ctx.Done():
	default:
		delete(l.pending, hash)
	}
}

func (l *LiveSync) downloadAddr(ctx context.Context, opts liveSyncOptions, id key.EndpointID) (netaddr.EndpointAddr, bool) {
	if addr, ok := l.resolvePeer(ctx, opts.Resolver, id); ok {
		return addr, true
	}
	for _, addr := range opts.Bootstrap {
		if addr.ID.Equal(id) {
			return addr, true
		}
	}
	return netaddr.EndpointAddr{}, false
}

func (l *LiveSync) runDownloader(ctx context.Context, store *MemoryStore, opts liveSyncOptions) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-l.downloads:
			if blobs.Status(opts.BlobStore, req.Hash).IsComplete() {
				store.contentReady(req.Hash)
				continue
			}
			if opts.downloadBlob == nil {
				continue
			}
			if err := opts.downloadBlob(ctx, req.Addr, req.Hash); err != nil {
				continue
			}
			store.contentReady(req.Hash)
			l.broadcastContentReady(ctx, req.Hash)
		}
	}
}

type liveDownload struct {
	Hash blobs.Hash
	Addr netaddr.EndpointAddr
}

type blobAdder interface {
	Add([]byte) (blobs.Hash, error)
}

func downloadBlob(ctx context.Context, ep *iroh.Endpoint, addr netaddr.EndpointAddr, store blobs.Store, hash blobs.Hash) error {
	if ep == nil {
		return errors.New("docs: nil endpoint")
	}
	add, ok := store.(blobAdder)
	if !ok {
		return errors.New("docs: blob store cannot add content")
	}
	conn, err := ep.Connect(ctx, addr, blobs.ALPN)
	if err != nil {
		return fmt.Errorf("docs: connect blob provider: %w", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("docs: open blob stream: %w", err)
	}
	data, err := blobs.GetBlobBytes(ctx, s, hash)
	if err != nil {
		return fmt.Errorf("docs: get blob: %w", err)
	}
	got, err := add.Add(data)
	if err != nil {
		return fmt.Errorf("docs: store blob: %w", err)
	}
	if got != hash {
		return fmt.Errorf("docs: stored blob hash mismatch")
	}
	return nil
}

func (l *LiveSync) syncPeers(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions, peers []netaddr.EndpointAddr) {
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
		if err == nil && outcome.NumRecv > 0 {
			l.broadcastSyncReport(ctx, namespace, store, opts)
		}
	}
}

func (l *LiveSync) broadcastSyncReport(ctx context.Context, namespace NamespaceID, store *MemoryStore, opts liveSyncOptions) {
	limit := opts.maxGossipPayloadSize
	if limit <= 0 {
		limit = gossipproto.DefaultMaxPayloadSize()
	}
	heads := store.encodeAuthorHeadsLimited(namespace, limit, func(heads []byte) bool {
		msg, err := marshalSyncReport(namespace, heads)
		return err == nil && len(msg) <= limit
	})
	msg, err := marshalSyncReport(namespace, heads)
	if err != nil {
		return
	}
	_ = l.topic.BroadcastNeighbors(ctx, msg)
}

func marshalSyncReport(namespace NamespaceID, heads []byte) ([]byte, error) {
	return postcard.Marshal(liveOp{Kind: liveOpSyncReport, Report: liveSyncReport{
		Namespace: namespace,
		Heads:     heads,
	}})
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
