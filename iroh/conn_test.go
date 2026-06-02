package iroh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/key"
)

// connPair binds a server and client endpoint on loopback, dials, and returns
// the dialed (client-side) and accepted (server-side) connections. Both
// endpoints and a context are cleaned up via t.Cleanup. The accepted conn is
// returned after the server's Accept completes so both ends are usable.
func connPair(t *testing.T, alpn string) (client, server *Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	srvKey, _ := key.GenerateSecretKey()
	srvEP, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvEP.Close(context.Background()) })

	clientEP, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientEP.Close(context.Background()) })

	type accepted struct {
		conn *Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := srvEP.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	addr := base.NewEndpointAddr(srvEP.ID()).WithIP(srvEP.LocalAddr())
	client, err = clientEP.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	return client, res.conn
}

// TestConnSide verifies the dialing side reports SideClient and the accepting
// side reports SideServer.
func TestConnSide(t *testing.T) {
	client, server := connPair(t, "iroh-side/0")
	defer client.Close(0, nil)
	defer server.Close(0, nil)

	if client.Side() != SideClient {
		t.Errorf("client.Side() = %v, want SideClient", client.Side())
	}
	if server.Side() != SideServer {
		t.Errorf("server.Side() = %v, want SideServer", server.Side())
	}
}

func TestSideString(t *testing.T) {
	tests := []struct {
		side Side
		want string
	}{
		{SideClient, "client"},
		{SideServer, "server"},
		{Side(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.side.String(); got != tt.want {
			t.Errorf("Side(%d).String() = %q, want %q", tt.side, got, tt.want)
		}
	}
}

// TestConnClose closes a connection with an application code and verifies the
// local side observes the close through Closed, CloseReason, and Context, and
// that the peer observes the same application code.
func TestConnClose(t *testing.T) {
	client, server := connPair(t, "iroh-close/0")

	// While open, none of the close observers report a close.
	select {
	case <-client.Closed():
		t.Fatal("Closed() fired while the connection was open")
	default:
	}
	if err := client.CloseReason(); err != nil {
		t.Fatalf("CloseReason() = %v while open, want nil", err)
	}
	if err := client.Context().Err(); err != nil {
		t.Fatalf("Context().Err() = %v while open, want nil", err)
	}

	const code = 42
	if err := client.Close(code, []byte("bye")); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The local side observes the close.
	select {
	case <-client.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("Closed() did not fire after local Close")
	}
	select {
	case <-client.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Context() not cancelled after local Close")
	}
	var appErr *quic.ApplicationError
	if err := client.CloseReason(); !errors.As(err, &appErr) {
		t.Fatalf("CloseReason() = %v, want *quic.ApplicationError", err)
	} else if uint64(appErr.ErrorCode) != code {
		t.Errorf("local CloseReason code = %d, want %d", appErr.ErrorCode, code)
	}

	// The peer observes the close carrying the same application code.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := server.AcceptStream(ctx)
	var peerErr *quic.ApplicationError
	if !errors.As(err, &peerErr) {
		t.Fatalf("peer AcceptStream err = %v, want *quic.ApplicationError", err)
	}
	if uint64(peerErr.ErrorCode) != code {
		t.Errorf("peer observed code %d, want %d", peerErr.ErrorCode, code)
	}
	if !peerErr.Remote {
		t.Error("peer's ApplicationError.Remote = false, want true (peer-initiated)")
	}

	// Closed and Context fire on the peer side too.
	select {
	case <-server.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("peer Closed() did not fire after remote close")
	}
}

// TestConnCloseOutOfRange checks that a code above the QUIC varint range is
// rejected without closing the connection.
func TestConnCloseOutOfRange(t *testing.T) {
	client, server := connPair(t, "iroh-closerange/0")
	defer client.Close(0, nil)
	defer server.Close(0, nil)

	err := client.Close(maxVarInt+1, nil)
	if err == nil {
		t.Fatal("Close with out-of-range code returned nil, want error")
	}

	// The connection must still be open: no close was sent.
	select {
	case <-client.Closed():
		t.Fatal("connection closed despite rejected close code")
	default:
	}
	if r := client.CloseReason(); r != nil {
		t.Errorf("CloseReason() = %v after rejected close, want nil", r)
	}

	// The connection is still usable: a stream round-trips.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		s, err := server.AcceptStream(ctx)
		if err != nil {
			return
		}
		b, _ := io.ReadAll(s)
		s.Write(b)
		s.Close()
	}()
	s, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream after rejected close: %v", err)
	}
	const msg = "still alive"
	s.Write([]byte(msg))
	s.Close()
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != msg {
		t.Errorf("echo = %q, want %q", got, msg)
	}
}

// TestConnPeerInitiatedClose verifies that a Close on one side is observed on
// the other side's Closed channel and CloseReason.
func TestConnPeerInitiatedClose(t *testing.T) {
	client, server := connPair(t, "iroh-peerclose/0")
	defer client.Close(0, nil)

	const code = 7
	if err := server.Close(code, []byte("server done")); err != nil {
		t.Fatalf("server Close: %v", err)
	}

	select {
	case <-client.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("client Closed() did not fire after peer close")
	}
	var appErr *quic.ApplicationError
	if err := client.CloseReason(); !errors.As(err, &appErr) {
		t.Fatalf("client CloseReason() = %v, want *quic.ApplicationError", err)
	} else if uint64(appErr.ErrorCode) != code {
		t.Errorf("client observed code %d, want %d", appErr.ErrorCode, code)
	}
}

// TestConnUniStream exercises OpenUniStream/AcceptUniStream end to end.
func TestConnUniStream(t *testing.T) {
	client, server := connPair(t, "iroh-uni/0")
	defer client.Close(0, nil)
	defer server.Close(0, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const msg = "uni hello"
	type result struct {
		data []byte
		err  error
	}
	got := make(chan result, 1)
	go func() {
		rs, err := server.AcceptUniStream(ctx)
		if err != nil {
			got <- result{err: err}
			return
		}
		b, err := io.ReadAll(rs)
		got <- result{data: b, err: err}
	}()

	ss, err := client.OpenUniStream(ctx)
	if err != nil {
		t.Fatalf("OpenUniStream: %v", err)
	}
	if _, err := ss.Write([]byte(msg)); err != nil {
		t.Fatalf("write uni: %v", err)
	}
	ss.Close()

	res := <-got
	if res.err != nil {
		t.Fatalf("read uni: %v", res.err)
	}
	if string(res.data) != msg {
		t.Errorf("uni stream = %q, want %q", res.data, msg)
	}
}

func TestEndpointConnectWith(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-connect-with/0"
	srvKey, _ := key.GenerateSecretKey()
	server, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close(ctx)

	accepted := make(chan error, 1)
	go func() {
		conn, err := server.Accept(ctx)
		if err == nil {
			err = conn.CloseWithError(0, "")
		}
		accepted <- err
	}()

	client, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close(ctx)

	connecting, err := client.ConnectWith(ctx, base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr()), []byte(alpn), ConnectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !connecting.RemoteID().Equal(server.ID()) {
		t.Fatalf("RemoteID = %s, want %s", connecting.RemoteID(), server.ID())
	}
	gotALPN, err := connecting.ALPN(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotALPN) != alpn {
		t.Fatalf("ALPN = %q, want %q", gotALPN, alpn)
	}
	conn, used0RTT := connecting.Into0RTT()
	if used0RTT {
		t.Fatal("first ConnectWith unexpectedly used 0-RTT")
	}
	if conn.StableID() == 0 {
		t.Fatal("StableID = 0, want non-zero")
	}
	if got, err := connecting.Connection(ctx); err != nil || got != conn {
		t.Fatalf("Connection = %v, %v; want original conn", got, err)
	}
	if clientStableIDCount(client) == 0 {
		t.Fatal("client stable ID map is empty before close")
	}
	conn.CloseWithError(0, "")
	if !waitFor(ctx, func() bool { return clientStableIDCount(client) == 0 }) {
		t.Fatalf("client stable ID map retained %d entries after close", clientStableIDCount(client))
	}
	if err := <-accepted; err != nil {
		t.Fatalf("accept: %v", err)
	}
}

func clientStableIDCount(e *Endpoint) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.stableIDs)
}

// ExampleConn_Close closes a loopback connection with an application code and
// reads it back from CloseReason.
func ExampleConn_Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-close-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs([]byte(alpn)),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Close(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Close(ctx)

	go server.Accept(ctx)

	addr := base.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, []byte(alpn))
	if err != nil {
		fmt.Println("connect:", err)
		return
	}

	conn.Close(42, []byte("done"))
	<-conn.Closed()

	var appErr *quic.ApplicationError
	if errors.As(conn.CloseReason(), &appErr) {
		fmt.Println("close code:", appErr.ErrorCode)
	}
	// Output:
	// close code: 42
}
