package iroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

func bindLocal(t testing.TB, ctx context.Context, opts ...Option) *Endpoint {
	t.Helper()
	opts = append([]Option{WithRelayMode(relay.ModeDisabled()), WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0"))}, opts...)
	ep, err := Bind(ctx, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ep.Shutdown(context.Background()) })
	return ep
}

func acceptLoop(ctx context.Context, ep *Endpoint) {
	for {
		c, err := ep.Accept(ctx)
		if err != nil {
			return
		}
		go func() { <-c.Context().Done() }()
	}
}

// TestConnectByIDUsesAddressBook: a bare EndpointID becomes dialable once its
// address was added to the endpoint, without the caller carrying it along.
func TestConnectByIDUsesAddressBook(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const alpn = "book/0"
	srv := bindLocal(t, ctx, WithALPNs(alpn))
	go acceptLoop(ctx, srv)
	cli := bindLocal(t, ctx)

	bare := netaddr.NewEndpointAddr(srv.ID())
	if _, err := cli.Connect(ctx, bare, alpn); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("Connect(bare) err = %v, want ErrNoAddress", err)
	}
	cli.AddEndpointAddr(srv.Addr())
	conn, err := cli.Connect(ctx, bare, alpn)
	if err != nil {
		t.Fatalf("Connect(bare) after AddEndpointAddr: %v", err)
	}
	conn.Close()
}

// TestConnectBackByID: after accepting a connection from X the endpoint can
// dial X by ID alone.
func TestConnectBackByID(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const alpn = "book/0"
	a := bindLocal(t, ctx, WithALPNs(alpn))
	b := bindLocal(t, ctx, WithALPNs(alpn))
	go acceptLoop(ctx, b)

	accepted := make(chan struct{})
	go func() {
		c, err := a.Accept(ctx)
		if err != nil {
			return
		}
		close(accepted)
		<-c.Context().Done()
	}()
	first, err := b.Connect(ctx, a.Addr(), alpn)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	<-accepted

	back, err := a.Connect(ctx, netaddr.NewEndpointAddr(b.ID()), alpn)
	if err != nil {
		t.Fatalf("connect back by ID: %v", err)
	}
	back.Close()
}
