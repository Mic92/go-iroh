package docs

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestSyncReportSkipsEqualHeads(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	entry := testSignedEntry(namespace, author, "k", testRecord("same", 1, 1))
	serverStore := NewMemoryStore()
	serverStore.Put(entry)
	clientStore := NewMemoryStore()
	clientStore.Put(entry)

	var splits atomic.Int64
	config := DefaultSyncConfig()
	config.splitHook = func(Range) { splits.Add(1) }
	server, router := newSyncReportNode(t, ctx, serverStore, config)
	defer router.Shutdown(ctx)
	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	outcome, err := Sync(ctx, client, addr, namespace.ID(), clientStore, nil, config)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if outcome != (SyncOutcome{}) {
		t.Fatalf("outcome = %+v, want zero", outcome)
	}
	if got := splits.Load(); got != 0 {
		t.Fatalf("range splits = %d, want 0", got)
	}
}

func TestSyncReportDivergentHeadsReconcile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	serverEntry := testSignedEntry(namespace, author, "server", testRecord("server", 1, 2))
	clientEntry := testSignedEntry(namespace, author, "client", testRecord("client", 1, 1))
	serverStore := NewMemoryStore()
	serverStore.Put(serverEntry)
	clientStore := NewMemoryStore()
	clientStore.Put(clientEntry)

	server, router := newSyncReportNode(t, ctx, serverStore, DefaultSyncConfig())
	defer router.Shutdown(ctx)
	client, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind client: %v", err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	outcome, err := Sync(ctx, client, addr, namespace.ID(), clientStore, nil, DefaultSyncConfig())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if outcome.NumSent == 0 || outcome.NumRecv == 0 {
		t.Fatalf("outcome = %+v, want range reconciliation", outcome)
	}
	if _, ok := serverStore.GetExact(namespace.ID(), author.ID(), []byte("client"), false); !ok {
		t.Fatal("server missing client entry")
	}
	if _, ok := clientStore.GetExact(namespace.ID(), author.ID(), []byte("server"), false); !ok {
		t.Fatal("client missing server entry")
	}
}

func newSyncReportNode(t *testing.T, ctx context.Context, store *MemoryStore, config SyncConfig) (*iroh.Endpoint, *iroh.Router) {
	t.Helper()
	ep, err := iroh.Bind(ctx, iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatalf("bind server: %v", err)
	}
	router, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		ALPN: &Handler{Store: store, Config: config},
	}, nil)
	if err != nil {
		t.Fatalf("new router: %v", err)
	}
	return ep, router
}
