package docs

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/blobs"
	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/internal/gossipproto"
	"github.com/tmc/go-iroh/internal/postcard"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestLiveOpPutRoundTrip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))

	data, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got liveOp
	if err := postcard.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Kind != liveOpPut || !got.Entry.Equal(entry) {
		t.Fatalf("op = %#v, want put entry", got)
	}
}

func TestLiveSyncReceivedPut(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}

	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()
	var l LiveSync
	l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: from.Public().EndpointID(),
		Scope:         gossip.DeliveryNeighbors,
	})

	got, ok := store.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok || !got.Equal(entry) {
		t.Fatal("received put was not inserted")
	}
	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertRemote || event.ContentStatus != ContentMissing {
		t.Fatalf("event = %#v, want remote missing insert", event)
	}
}

func TestLiveSyncReceivedSwarmPutMarksMissing(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	msg, err := postcard.Marshal(liveOp{Kind: liveOpPut, Entry: entry})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	store := NewMemoryStore()
	events, cancel := store.Subscribe()
	defer cancel()
	var l LiveSync
	l.handleReceived(context.Background(), namespace.ID(), store, liveSyncOptions{}, gossip.Event{
		Kind:    gossip.Received,
		Content: msg,
		Scope:   gossip.DeliverySwarm,
		Round:   2,
	})

	event := readStoreEvent(t, events)
	if event.Kind != StoreEventInsertRemote || event.ContentStatus != ContentMissing {
		t.Fatalf("event = %#v, want remote missing insert", event)
	}
}

func TestLiveSyncDownloadsRemoteContent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	content := []byte("content fetched by live sync")
	contentHash := blobs.NewHash(content)
	entry := testSignedEntry(namespace, author, "k", NewRecord(contentHash, uint64(len(content)), 1))

	aStore := NewMemoryStore()
	aBlobs, err := blobs.NewBytesMap(content)
	if err != nil {
		t.Fatalf("NewBytesMap: %v", err)
	}
	a, aGossip, aRouter := newLiveSyncNode(t, ctx, aStore, aBlobs)
	defer aRouter.Shutdown(ctx)

	bStore := NewMemoryStore()
	bBlobs, err := blobs.NewBytesMap()
	if err != nil {
		t.Fatalf("NewBytesMap: %v", err)
	}
	b, bGossip, bRouter := newLiveSyncNode(t, ctx, bStore, bBlobs)
	defer bRouter.Shutdown(ctx)

	aAddr := netaddr.NewEndpointAddr(a.ID()).WithIP(a.LocalAddr())
	bEvents, cancelEvents := bStore.Subscribe()
	defer cancelEvents()

	aLive, err := StartLiveSync(ctx, a, aGossip, namespace.ID(), aStore, LiveSyncOptions{
		BlobStore: aBlobs,
	})
	if err != nil {
		t.Fatalf("start a live sync: %v", err)
	}
	defer aLive.Close()
	bLive, err := StartLiveSync(ctx, b, bGossip, namespace.ID(), bStore, LiveSyncOptions{
		Bootstrap: []netaddr.EndpointAddr{aAddr},
		Resolver:  iroh.StaticLookupFromAddrs(aAddr),
		BlobStore: bBlobs,
	})
	if err != nil {
		t.Fatalf("start b live sync: %v", err)
	}
	defer bLive.Close()
	if err := bLive.topic.Joined(ctx); err != nil {
		t.Fatalf("b joined: %v", err)
	}

	aStore.Put(entry)

	var ready bool
	for !ready {
		select {
		case ev := <-bEvents:
			switch ev.Kind {
			case StoreEventInsertRemote:
				if ev.ContentStatus != ContentMissing {
					t.Fatalf("remote insert status = %v, want missing", ev.ContentStatus)
				}
			case StoreEventContentReady:
				if ev.Hash != contentHash {
					t.Fatalf("content ready hash = %s, want %s", ev.Hash, contentHash)
				}
				ready = true
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	got, ok := bBlobs.GetBlob(contentHash)
	if !ok {
		t.Fatal("downloaded blob missing from b store")
	}
	if string(got) != string(content) {
		t.Fatalf("downloaded blob = %q, want %q", got, content)
	}
}

func newLiveSyncNode(t *testing.T, ctx context.Context, store *MemoryStore, blobStore *blobs.BytesMap) (*iroh.Endpoint, *gossip.Gossip, *iroh.Router) {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind endpoint: %v", err)
	}
	g := gossip.NewGossip(ep)
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		blobs.ALPN:  liveBlobHandler{store: blobStore},
		ALPN:        &Handler{Store: store, BlobStore: blobStore},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return ep, g, router
}

type liveBlobHandler struct {
	store blobs.Store
}

func (h liveBlobHandler) Accept(ctx context.Context, conn *iroh.Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	return blobs.ServeBlob(ctx, s, h.store)
}

func TestLiveSyncReportTriggersSync(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	from, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}
	fromID := from.Public().EndpointID()
	addr := netaddr.NewEndpointAddr(fromID)
	msg, err := postcard.Marshal(liveOp{
		Kind: liveOpSyncReport,
		Report: liveSyncReport{
			Namespace: namespace.ID(),
			Heads:     []byte{1, 2, 3},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	called := make(chan netaddr.EndpointAddr, 1)
	var l LiveSync
	l.handleReceived(ctx, namespace.ID(), NewMemoryStore(), liveSyncOptions{
		LiveSyncOptions: LiveSyncOptions{Resolver: iroh.StaticLookupFromAddrs(addr)},
		syncPeer: func(ctx context.Context, peer netaddr.EndpointAddr) (SyncOutcome, error) {
			called <- peer
			return SyncOutcome{}, nil
		},
	}, gossip.Event{
		Kind:          gossip.Received,
		Content:       msg,
		DeliveredFrom: fromID,
	})

	select {
	case got := <-called:
		if !got.ID.Equal(fromID) {
			t.Fatalf("sync peer = %s, want %s", got.ID, fromID)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLiveSyncReportAuthorHeadsLimited(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	for i := 0; i < 40; i++ {
		var seed [32]byte
		seed[0] = byte(i + 1)
		author := NewAuthor(seed)
		entry := testSignedEntry(namespace, author, "k", testRecord("one", 1, uint64(i+1)))
		store.Put(entry)
	}

	all := store.encodeAuthorHeads(namespace.ID())
	allMsg, err := marshalSyncReport(namespace.ID(), all)
	if err != nil {
		t.Fatalf("marshal full report: %v", err)
	}
	limit := len(allMsg) - 200
	if limit <= 0 {
		t.Fatalf("test limit %d is not positive", limit)
	}
	heads := store.encodeAuthorHeadsLimited(namespace.ID(), limit, func(heads []byte) bool {
		msg, err := marshalSyncReport(namespace.ID(), heads)
		return err == nil && len(msg) <= limit
	})
	msg, err := marshalSyncReport(namespace.ID(), heads)
	if err != nil {
		t.Fatalf("marshal limited report: %v", err)
	}
	if len(msg) > limit {
		t.Fatalf("limited report size = %d, want <= %d", len(msg), limit)
	}

	var got []authorHead
	if err := postcard.Unmarshal(heads, &got); err != nil {
		t.Fatalf("unmarshal heads: %v", err)
	}
	if len(got) == 0 || len(got) >= 40 {
		t.Fatalf("limited heads len = %d, want between 1 and 39", len(got))
	}
	for i, head := range got {
		want := uint64(40 - i)
		if head.Timestamp != want {
			t.Fatalf("head %d timestamp = %d, want newest timestamp %d", i, head.Timestamp, want)
		}
	}
}

func TestLiveSyncReportFitsGossipPayloadBudget(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	store := NewMemoryStore()
	for i := 0; i < 120; i++ {
		var seed [32]byte
		seed[0] = byte(i + 1)
		seed[1] = byte(i / 255)
		author := NewAuthor(seed)
		store.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, uint64(i+1))))
	}

	limit := gossipproto.MaxPayloadSize(gossipproto.MinMaxMessageSize)
	heads := store.encodeAuthorHeadsLimited(namespace.ID(), limit, func(heads []byte) bool {
		msg, err := marshalSyncReport(namespace.ID(), heads)
		return err == nil && len(msg) <= limit
	})
	msg, err := marshalSyncReport(namespace.ID(), heads)
	if err != nil {
		t.Fatalf("marshal sync report: %v", err)
	}
	if len(msg) > limit {
		t.Fatalf("sync report size = %d, want <= %d", len(msg), limit)
	}
}
