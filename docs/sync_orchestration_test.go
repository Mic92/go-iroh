package docs

import (
	"context"
	"errors"
	"iter"
	"net/netip"
	"testing"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

func TestSyncTicketUsesResolver(t *testing.T) {
	ctx := context.Background()
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	node := netaddr.NewEndpointAddr(sk.Public().EndpointID())
	resolved := node.WithIP(netip.AddrPortFrom(netip.IPv6Loopback(), 12345))
	ticket := NewTicket(NewReadCapability(NewNamespaceSecret(repeat32(0xb2)).ID()), []netaddr.EndpointAddr{node})

	addrs := ticketAddrs(ctx, ticket.Nodes(), iroh.AddressResolverFunc(func(ctx context.Context, id key.EndpointID) iter.Seq2[iroh.Item, error] {
		if !id.Equal(node.ID) {
			return nil
		}
		return func(yield func(iroh.Item, error) bool) {
			yield(iroh.NewItem(dns.EndpointInfoFromAddr(resolved), "test", nil), nil)
		}
	}))
	if len(addrs) != 2 {
		t.Fatalf("len(addrs) = %d, want 2", len(addrs))
	}
	if !addrs[0].ID.Equal(node.ID) || !addrs[1].ID.Equal(node.ID) {
		t.Fatal("resolved addrs have wrong endpoint id")
	}
	if len(addrs[1].Addrs()) == 0 {
		t.Fatal("resolver address was not included")
	}
}

func TestSyncErrors(t *testing.T) {
	errBoom := errors.New("boom")
	results := []SyncResult{
		{Err: nil},
		{Addr: netaddr.NewEndpointAddr(key.EndpointID{}), Err: errBoom},
	}
	if err := SyncErrors(results); !errors.Is(err, errBoom) {
		t.Fatalf("SyncErrors = %v, want boom", err)
	}
}
