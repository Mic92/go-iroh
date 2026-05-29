package iroh

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	tls "github.com/tmc/go-iroh/internal/itls/tls"
	quic "github.com/tmc/go-iroh/internal/qng"
)

// TestEndpoint0RTTResumption is the slice-E gate: a client connects to a server
// twice. The first connection completes a full handshake and the server issues
// a TLS session ticket, which the client caches. The second connection resumes
// that session and is established with 0-RTT early data; the test asserts the
// 0-RTT path was used on both ends.
func TestEndpoint0RTTResumption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const alpn = "iroh-0rtt/0"

	srvKey, _ := base.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	// Server echo loop: accept connections and echo one bidi stream each. It
	// keeps each connection open until the client closes it so the post-handshake
	// NewSessionTicket reaches the client.
	srvErr := make(chan error, 4)
	go func() {
		for {
			conn, err := server.Accept(ctx)
			if err != nil {
				srvErr <- err
				return
			}
			go func() {
				s, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				b, _ := io.ReadAll(s)
				s.Write(b)
				s.Close()
			}()
		}
	}()

	addr := base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())

	// First connection: full handshake. The server issues a session ticket that
	// the client caches after the handshake.
	conn1, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if conn1.Used0RTT() {
		t.Error("first connection unexpectedly used 0-RTT (no ticket was cached yet)")
	}
	echo(t, ctx, conn1, "first")

	// The NewSessionTicket arrives asynchronously after the handshake. Wait for
	// the client to cache at least one ticket for the server before resuming.
	if !waitFor(ctx, func() bool { return client.sessionCache.Len() > 0 }) {
		t.Fatalf("client never cached a session ticket: %v", ctx.Err())
	}
	conn1.CloseWithError(0, "")

	// Second connection: should resume via 0-RTT. Connect returns the early
	// connection before the handshake completes, so we send 0-RTT data
	// immediately, then wait for the handshake to confirm the server accepted it.
	conn2, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("second connect: %v", err)
	}
	defer conn2.CloseWithError(0, "")

	s, err := conn2.OpenStream(ctx)
	if err != nil {
		t.Fatalf("second open stream: %v", err)
	}
	const msg = "second"
	s.Write([]byte(msg))
	s.Close()

	select {
	case <-conn2.HandshakeComplete():
	case <-ctx.Done():
		t.Fatalf("second handshake did not complete: %v", ctx.Err())
	}
	if !conn2.Used0RTT() {
		t.Error("second connection did not use 0-RTT despite a cached ticket")
	}

	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("second read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("second echo = %q, want %q", got, msg)
	}
	if !conn2.RemoteID().Equal(server.ID()) {
		t.Errorf("resumed connection remote id = %s, want %s", conn2.RemoteID(), server.ID())
	}
}

// echo opens a bidi stream on conn, writes msg, and checks the echoed reply.
func echo(t *testing.T, ctx context.Context, conn *Conn, msg string) {
	t.Helper()
	s, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("%s open stream: %v", msg, err)
	}
	s.Write([]byte(msg))
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("%s read echo: %v", msg, err)
	}
	if string(got) != msg {
		t.Errorf("%s echo = %q, want %q", msg, got, msg)
	}
}

// waitFor polls cond until it is true or ctx is done.
func waitFor(ctx context.Context, cond func() bool) bool {
	for {
		if cond() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestIroh0RTTRejectedFallsBackToFullHandshake checks the rejection path: a
// client holding a valid session ticket dials a server that does not accept
// 0-RTT. The QUIC stack must reject the early data and complete a full
// handshake, leaving Used0RTT false and the connection otherwise usable. This is
// run directly against the qng transport so the server's 0-RTT acceptance can be
// toggled per listener.
func TestIroh0RTTRejectedFallsBackToFullHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	serverKey, _ := base.GenerateSecretKey()
	clientKey, _ := base.GenerateSecretKey()
	const alpn = "iroh-0rtt/0"

	cache := tls.NewLRUClientSessionCache(maxTLSTickets)

	// First, prime the client cache with a ticket from a server that allows
	// 0-RTT, so the client has something to resume with.
	used := dialOnceForTicket(t, ctx, serverKey, clientKey, alpn, cache, true)
	if used {
		t.Fatal("priming connection should not have used 0-RTT")
	}
	if !waitFor(ctx, func() bool {
		_, ok := cache.Get(ServerName(serverKey.Public()))
		return ok
	}) {
		t.Fatalf("no ticket cached after priming: %v", ctx.Err())
	}

	// Now resume against a server with the SAME identity (so the SNI/cache key
	// matches) but a fresh token-generator key and 0-RTT disabled. The server
	// rejects the 0-RTT attempt; the handshake still completes normally.
	used = dialOnceForTicket(t, ctx, serverKey, clientKey, alpn, cache, false)
	if used {
		t.Error("0-RTT was accepted by a server that does not allow it")
	}
}

// dialOnceForTicket stands up a qng server with serverKey (allowing 0-RTT iff
// allow0RTT) and a client that dials it with the iroh TLS configs and the given
// session cache. It echoes one stream, returns whether the client connection
// used 0-RTT, and tears both sides down.
func dialOnceForTicket(t *testing.T, ctx context.Context, serverKey, clientKey base.SecretKey, alpn string, cache tls.ClientSessionCache, allow0RTT bool) bool {
	t.Helper()

	serverTLS, err := serverTLSConfig(serverKey, []string{alpn})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := clientTLSConfig(clientKey, serverKey.Public(), []string{alpn}, cache)
	if err != nil {
		t.Fatal(err)
	}

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	serverTr := &quic.Transport{Conn: serverUDP}
	defer serverTr.Close()
	defer serverUDP.Close()

	ln, err := serverTr.ListenEarly(serverTLS, &quic.Config{Allow0RTT: allow0RTT})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		select {
		case <-conn.HandshakeComplete():
		case <-ctx.Done():
			return
		}
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(b)
		s.Close()
		// Keep the connection open so the session ticket reaches the client.
		<-conn.Context().Done()
	}()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	clientTr := &quic.Transport{Conn: clientUDP}
	defer clientTr.Close()
	defer clientUDP.Close()

	conn, err := clientTr.DialEarly(ctx, ln.Addr(), clientTLS, &quic.Config{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		t.Fatalf("handshake did not complete: %v", ctx.Err())
	}

	s, err := conn.OpenStreamSync(ctx)
	if errors.Is(err, quic.Err0RTTRejected) {
		// The server rejected 0-RTT: every stream opened on the early connection
		// is reset and keeps returning Err0RTTRejected until the application moves
		// to the post-handshake connection with NextConnection (the qng analog of
		// the Rust ZeroRttStatus::Rejected branch). After that, streams open
		// normally over the completed 1-RTT handshake.
		conn, err = conn.NextConnection(ctx)
		if err != nil {
			t.Fatalf("next connection after 0-RTT rejection: %v", err)
		}
		s, err = conn.OpenStreamSync(ctx)
	}
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	const msg = "ping"
	s.Write([]byte(msg))
	s.Close()
	if _, err := io.ReadAll(s); err != nil && !errors.Is(err, quic.Err0RTTRejected) {
		t.Fatalf("read echo: %v", err)
	}

	used := conn.ConnectionState().Used0RTT
	// Give the server a moment to deliver the NewSessionTicket before teardown.
	waitFor(ctx, func() bool {
		_, ok := cache.Get(ServerName(serverKey.Public()))
		return ok
	})
	conn.CloseWithError(0, "")
	return used
}
