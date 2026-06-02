package iroh

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

type testHooks struct {
	before func(context.Context, netaddr.EndpointAddr, []byte) (BeforeConnectOutcome, error)
	after  func(context.Context, *Conn) (AfterHandshakeOutcome, error)
}

func (h testHooks) BeforeConnect(ctx context.Context, addr netaddr.EndpointAddr, alpn []byte) (BeforeConnectOutcome, error) {
	if h.before != nil {
		return h.before(ctx, addr, alpn)
	}
	return BeforeConnectAccept, nil
}

func (h testHooks) AfterHandshake(ctx context.Context, conn *Conn) (AfterHandshakeOutcome, error) {
	if h.after != nil {
		return h.after(ctx, conn)
	}
	return AcceptHandshake(), nil
}

func TestEndpointHooksRejectBeforeConnect(t *testing.T) {
	ctx := context.Background()
	client, err := Bind(ctx, WithHooks(testHooks{
		before: func(context.Context, netaddr.EndpointAddr, []byte) (BeforeConnectOutcome, error) {
			return BeforeConnectReject, nil
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	sk, _ := key.GenerateSecretKey()
	addr := netaddr.NewEndpointAddr(sk.Public()).WithIP(netip.MustParseAddrPort("127.0.0.1:1"))
	if _, err := client.Connect(ctx, addr, []byte("iroh-hooks/0")); !errors.Is(err, ErrConnectRejected) {
		t.Fatalf("Connect err = %v, want ErrConnectRejected", err)
	}
}

func TestEndpointHooksRejectAfterHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-hooks/0"
	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx,
		WithSecretKey(srvKey),
		WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)),
		WithHooks(testHooks{
			after: func(context.Context, *Conn) (AfterHandshakeOutcome, error) {
				return RejectHandshake(77, []byte("blocked")), nil
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	accepted := make(chan error, 1)
	go func() {
		_, err := server.Accept(ctx)
		accepted <- err
	}()

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	conn, err := client.Connect(ctx, netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), []byte(alpn))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")

	if err := <-accepted; !errors.Is(err, ErrHandshakeRejected) {
		t.Fatalf("Accept err = %v, want ErrHandshakeRejected", err)
	}
	select {
	case <-conn.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("client did not observe hook rejection close")
	}
}
