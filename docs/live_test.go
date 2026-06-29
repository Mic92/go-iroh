package docs

import (
	"context"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
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
	if event.Kind != StoreEventInsertRemote || event.ContentStatus != ContentComplete {
		t.Fatalf("event = %#v, want remote complete insert", event)
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
