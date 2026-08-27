package gossip_test

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tmc/go-iroh/gossip"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

type discNode struct {
	ep   *iroh.Endpoint
	disc *gossip.Discovery
}

// startDiscNode binds an endpoint whose address lookup is the gossip
// Discovery itself, so publishing and resolving need no glue code.
func startDiscNode(t *testing.T, ctx context.Context, topic gossip.TopicID, bootstrap []netaddr.EndpointAddr) discNode {
	t.Helper()
	const alpn = "disc-test/0"
	svcs := &iroh.AddressLookupServices{}
	ep, err := iroh.Bind(ctx,
		iroh.WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		iroh.WithALPNs(alpn),
		iroh.WithAddressLookup(svcs))
	if err != nil {
		t.Fatal(err)
	}
	g := gossip.NewGossip(ep)
	r, err := iroh.NewRouter(ep, map[string]iroh.ProtocolHandler{
		gossip.ALPN: g.Handler(),
		alpn: iroh.ProtocolHandlerFunc(func(ctx context.Context, c *iroh.Conn) error {
			<-c.Context().Done()
			return nil
		}),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Shutdown(context.Background()) })
	d := gossip.New(ep.ID(), gossip.WithGossip(g, topic, bootstrap))
	svcs.AddPublisher(d)
	svcs.AddResolver(d)
	go d.Start(ctx)
	return discNode{ep: ep, disc: d}
}

// TestDiscoveryEnumeratesAndDials: A and C only know B. A must learn that C
// exists from the swarm and be able to dial it by ID.
func TestDiscoveryEnumeratesAndDials(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var topic gossip.TopicID
	copy(topic[:], "swarm")

	b := startDiscNode(t, ctx, topic, nil)
	boot := []netaddr.EndpointAddr{b.ep.Addr()}
	a := startDiscNode(t, ctx, topic, boot)
	c := startDiscNode(t, ctx, topic, boot)

	for !slices.ContainsFunc(a.disc.Peers(), func(id key.EndpointID) bool { return id.Equal(c.ep.ID()) }) {
		select {
		case <-a.disc.Updated():
		case <-ctx.Done():
			t.Fatalf("A never learned about C; peers=%v", a.disc.Peers())
		}
	}
	conn, err := a.ep.Connect(ctx, netaddr.NewEndpointAddr(c.ep.ID()), "disc-test/0")
	if err != nil {
		t.Fatalf("A dial C by ID: %v", err)
	}
	conn.Close()
}
