package iroh

import (
	"context"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

// echoHandler is a ProtocolHandler that echoes one bidirectional stream back to
// the peer and then returns.
type echoHandler struct{}

func (echoHandler) Accept(ctx context.Context, conn *Conn) error {
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(s)
	if err != nil {
		return err
	}
	if _, err := s.Write(b); err != nil {
		return err
	}
	return s.Close()
}

// shutdownEcho records whether Shutdown was called, exercising the optional
// ShutdownHandler hook.
type shutdownEcho struct {
	echoHandler
	mu   sync.Mutex
	done bool
}

func (h *shutdownEcho) Shutdown(ctx context.Context) {
	h.mu.Lock()
	h.done = true
	h.mu.Unlock()
}

func (h *shutdownEcho) wasShutdown() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.done
}

type blockingShutdown struct {
	started chan struct{}
	release <-chan struct{}
}

func (h blockingShutdown) Accept(context.Context, *Conn) error { return nil }

func (h blockingShutdown) Shutdown(ctx context.Context) {
	close(h.started)
	select {
	case <-h.release:
	case <-ctx.Done():
	}
}

type panicHandler struct {
	started chan struct{}
}

func (h panicHandler) Accept(context.Context, *Conn) error {
	close(h.started)
	panic("router panic test")
}

type acceptingEcho struct {
	echoHandler
	called chan string
}

func (h acceptingEcho) OnAccepting(ctx context.Context, accepting *Accepting) (*Conn, error) {
	alpn, err := accepting.ALPN(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case h.called <- alpn:
	default:
	}
	return accepting.Connection(ctx)
}

// TestRouterEcho is the slice-H Router gate: two endpoints connect over a direct
// loopback path; the server registers an echo ProtocolHandler via a Router; the
// client connects and exchanges a stream echo dispatched by ALPN through the
// Router.
func TestRouterEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-echo/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	h := &shutdownEcho{}
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: h}, nil)
	if err != nil {
		t.Fatalf("spawn router: %v", err)
	}
	defer router.Shutdown(ctx)

	if router.Endpoint() != server {
		t.Error("Router.Endpoint did not return the server endpoint")
	}
	if router.IsShutdown() {
		t.Error("router reported shutdown before Shutdown was called")
	}

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const msg = "hello router"
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}

	// Shutting down the router cancels the loop, runs handler Shutdown, and
	// closes the endpoint.
	if err := router.Shutdown(ctx); err != nil {
		t.Errorf("shutdown: %v", err)
	}
	if !router.IsShutdown() {
		t.Error("router did not report shutdown after Shutdown")
	}
	if !h.wasShutdown() {
		t.Error("handler Shutdown hook was not called")
	}
}

func TestRouterFilterRetryUsesQUICRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-retry/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	var retryCalls atomic.Int32
	var acceptedValidated atomic.Bool
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: echoHandler{}}, &RouterConfig{
		IncomingFilter: func(in *Incoming) IncomingFilterOutcome {
			if in.RemoteAddrValidated() {
				acceptedValidated.Store(true)
				return FilterAccept
			}
			retryCalls.Add(1)
			return FilterRetry
		},
	})
	if err != nil {
		t.Fatalf("spawn router: %v", err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := s.Write([]byte("retry")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "retry" {
		t.Fatalf("echo = %q, want retry", got)
	}
	if retryCalls.Load() == 0 {
		t.Fatal("filter did not request pre-connection retry")
	}
	if !acceptedValidated.Load() {
		t.Fatal("post-retry incoming was not remote-address validated")
	}
}

// TestRouterUnsupportedALPN checks that a connection negotiating an ALPN with no
// registered handler is closed by the router (and the rest keeps working).
func TestRouterUnsupportedALPN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const goodALPN = "iroh-good/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewRouter(server, map[string]ProtocolHandler{goodALPN: echoHandler{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	// The server only advertises goodALPN, so a client offering only an unknown
	// ALPN fails the handshake at the QUIC/TLS layer.
	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	if _, err := client.Connect(ctx, addr, "iroh-unknown/0"); err == nil {
		t.Error("connect with unknown ALPN unexpectedly succeeded")
	}

	// A subsequent good connection still works, proving the loop survived.
	conn, err := client.Connect(ctx, addr, goodALPN)
	if err != nil {
		t.Fatalf("good connect after bad: %v", err)
	}
	conn.CloseWithError(0, "")
}

func TestRouterHandlerPanicDoesNotStopAcceptLoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const (
		panicALPN = "iroh-router-panic/0"
		echoALPN  = "iroh-router-after-panic/0"
	)

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	panicStarted := make(chan struct{})
	router, err := NewRouter(server, map[string]ProtocolHandler{
		panicALPN: panicHandler{started: panicStarted},
		echoALPN:  echoHandler{},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	panicConn, err := client.Connect(ctx, addr, panicALPN)
	if err != nil {
		t.Fatalf("panic connect: %v", err)
	}
	panicConn.CloseWithError(0, "")
	select {
	case <-panicStarted:
	case <-ctx.Done():
		t.Fatal("panic handler was not called")
	}

	conn, err := client.Connect(ctx, addr, echoALPN)
	if err != nil {
		t.Fatalf("connect after panic: %v", err)
	}
	defer conn.CloseWithError(0, "")
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("open stream after panic: %v", err)
	}
	const msg = "after panic"
	if _, err := s.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo after panic: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo after panic = %q, want %q", got, msg)
	}
}

func TestRouterShutdownHandlersRunConcurrently(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	server, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	release := make(chan struct{})
	h1 := blockingShutdown{started: make(chan struct{}), release: release}
	h2 := blockingShutdown{started: make(chan struct{}), release: release}
	router, err := NewRouter(server, map[string]ProtocolHandler{
		"iroh-shutdown-a/0": h1,
		"iroh-shutdown-b/0": h2,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		done <- router.Shutdown(ctx)
	}()

	select {
	case <-h1.started:
	case <-time.After(time.Second):
		t.Fatal("first handler Shutdown was not called")
	}
	select {
	case <-h2.started:
	case <-time.After(time.Second):
		t.Fatal("second handler Shutdown was not called concurrently")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestRouterOnAccepting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-router-accepting/0"

	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}

	called := make(chan string, 1)
	router, err := NewRouter(server, map[string]ProtocolHandler{alpn: acceptingEcho{called: called}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Shutdown(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Shutdown(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.CloseWithError(0, "")

	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("accepting")); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := io.ReadAll(s); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-called:
		if got != alpn {
			t.Fatalf("OnAccepting ALPN = %q, want %q", got, alpn)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
