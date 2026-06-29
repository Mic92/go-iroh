package iroh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
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
	srvEP, err := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srvEP.Shutdown(context.Background()) })

	clientEP, err := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clientEP.Shutdown(context.Background()) })

	type accepted struct {
		conn *Conn
		err  error
	}
	done := make(chan accepted, 1)
	go func() {
		c, err := srvEP.Accept(ctx)
		done <- accepted{conn: c, err: err}
	}()

	addr := netaddr.NewEndpointAddr(srvEP.ID()).WithIP(srvEP.LocalAddr())
	client, err = clientEP.Connect(ctx, addr, alpn)
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
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	if client.Side() != SideClient {
		t.Errorf("client.Side() = %v, want SideClient", client.Side())
	}
	if server.Side() != SideServer {
		t.Errorf("server.Side() = %v, want SideServer", server.Side())
	}
}

func TestConnAddr(t *testing.T) {
	client, server := connPair(t, "iroh-addr/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	if client.LocalAddr() == nil {
		t.Fatal("client.LocalAddr() = nil")
	}
	if client.RemoteAddr() == nil {
		t.Fatal("client.RemoteAddr() = nil")
	}
	if server.LocalAddr() == nil {
		t.Fatal("server.LocalAddr() = nil")
	}
	if server.RemoteAddr() == nil {
		t.Fatal("server.RemoteAddr() = nil")
	}
}

func TestConnStats(t *testing.T) {
	client, server := connPair(t, "iroh-stats/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		s, err := server.AcceptStream(ctx)
		if err != nil {
			done <- err
			return
		}
		if _, err := io.Copy(s, s); err != nil {
			done <- err
			return
		}
		done <- s.Close()
	}()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := io.ReadAll(s); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		conn *Conn
	}{
		{"client", client},
		{"server", server},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.conn.Stats()
			want := tt.conn.qc.ConnectionStats()
			if got.MinRTT != want.MinRTT {
				t.Errorf("MinRTT = %v, want %v", got.MinRTT, want.MinRTT)
			}
			if got.LatestRTT != want.LatestRTT {
				t.Errorf("LatestRTT = %v, want %v", got.LatestRTT, want.LatestRTT)
			}
			if got.SmoothedRTT != want.SmoothedRTT {
				t.Errorf("SmoothedRTT = %v, want %v", got.SmoothedRTT, want.SmoothedRTT)
			}
			if got.MeanDeviation != want.MeanDeviation {
				t.Errorf("MeanDeviation = %v, want %v", got.MeanDeviation, want.MeanDeviation)
			}
			if got.BytesSent != want.BytesSent {
				t.Errorf("BytesSent = %d, want %d", got.BytesSent, want.BytesSent)
			}
			if got.PacketsSent != want.PacketsSent {
				t.Errorf("PacketsSent = %d, want %d", got.PacketsSent, want.PacketsSent)
			}
			if got.BytesReceived != want.BytesReceived {
				t.Errorf("BytesReceived = %d, want %d", got.BytesReceived, want.BytesReceived)
			}
			if got.PacketsReceived != want.PacketsReceived {
				t.Errorf("PacketsReceived = %d, want %d", got.PacketsReceived, want.PacketsReceived)
			}
			if got.BytesLost != want.BytesLost {
				t.Errorf("BytesLost = %d, want %d", got.BytesLost, want.BytesLost)
			}
			if got.PacketsLost != want.PacketsLost {
				t.Errorf("PacketsLost = %d, want %d", got.PacketsLost, want.PacketsLost)
			}
			if got.BytesSent == 0 {
				t.Error("BytesSent = 0, want traffic recorded")
			}
			if got.BytesReceived == 0 {
				t.Error("BytesReceived = 0, want traffic recorded")
			}
		})
	}
}

func TestConnPaths(t *testing.T) {
	client, server := connPair(t, "iroh-paths/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	tests := []struct {
		name string
		conn *Conn
	}{
		{"client", client},
		{"server", server},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := tt.conn.Paths()
			if len(paths) == 0 {
				t.Fatal("Paths() returned no paths")
			}
			var selected int
			for _, p := range paths {
				if p.Selected {
					selected++
				}
				if p.Selected && !p.Validated {
					t.Errorf("selected path is not validated: %+v", p)
				}
				if p.Selected && !p.HasAddr {
					t.Errorf("selected path has no address: %+v", p)
				}
				if p.Relayed {
					t.Errorf("loopback path Relayed = true, want false: %+v", p)
				}
			}
			if selected != 1 {
				t.Fatalf("selected path count = %d, want 1; paths=%+v", selected, paths)
			}
		})
	}
}

func TestConnWatchPaths(t *testing.T) {
	client, server := connPair(t, "iroh-watch-paths/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	watch, err := client.WatchPaths(ctx)
	if err != nil {
		t.Fatalf("WatchPaths: %v", err)
	}
	select {
	case paths, ok := <-watch:
		if !ok {
			t.Fatal("WatchPaths closed before initial snapshot")
		}
		var selected bool
		for _, p := range paths {
			selected = selected || p.Selected
		}
		if !selected {
			t.Fatalf("initial WatchPaths snapshot has no selected path: %+v", paths)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestStreamConn(t *testing.T) {
	client, server := connPair(t, "iroh-stream-conn/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		c, err := server.AcceptStreamConn(ctx)
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		if c.LocalAddr() == nil || c.RemoteAddr() == nil {
			done <- errors.New("stream conn missing addresses")
			return
		}
		var _ net.Conn = c
		b, err := io.ReadAll(c)
		if err != nil {
			done <- err
			return
		}
		if string(b) != "hello" {
			done <- fmt.Errorf("read %q, want hello", string(b))
			return
		}
		done <- nil
	}()

	c, err := client.OpenStreamConn(ctx)
	if err != nil {
		t.Fatalf("OpenStreamConn: %v", err)
	}
	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("stream conn missing addresses")
	}
	var _ net.Conn = c
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
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

// TestConnCloseWithError closes a connection with an application code and
// verifies that both sides observe the same application code.
func TestConnCloseWithError(t *testing.T) {
	client, server := connPair(t, "iroh-close/0")

	// While open, none of the close observers report a close.
	select {
	case <-client.Context().Done():
		t.Fatal("Context() fired while the connection was open")
	default:
	}
	if err := client.Context().Err(); err != nil {
		t.Fatalf("Context().Err() = %v while open, want nil", err)
	}

	const code = 42
	if err := client.CloseWithError(code, "bye"); err != nil {
		t.Fatalf("CloseWithError: %v", err)
	}

	// The local side observes the close.
	select {
	case <-client.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("Context() did not fire after local Close")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(client.Context()); !errors.As(err, &appErr) {
		t.Fatalf("context cause = %v, want *quic.ApplicationError", err)
	} else if uint64(appErr.ErrorCode) != code {
		t.Errorf("local close code = %d, want %d", appErr.ErrorCode, code)
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

	select {
	case <-server.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("peer Context() did not fire after remote close")
	}
}

// TestConnPeerInitiatedClose verifies that CloseWithError on one side is
// observed on the other side's context cause.
func TestConnPeerInitiatedClose(t *testing.T) {
	client, server := connPair(t, "iroh-peerclose/0")
	defer client.CloseWithError(0, "")

	const code = 7
	if err := server.CloseWithError(code, "server done"); err != nil {
		t.Fatalf("server CloseWithError: %v", err)
	}

	select {
	case <-client.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("client Context() did not fire after peer close")
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(client.Context()); !errors.As(err, &appErr) {
		t.Fatalf("client context cause = %v, want *quic.ApplicationError", err)
	} else if uint64(appErr.ErrorCode) != code {
		t.Errorf("client observed code %d, want %d", appErr.ErrorCode, code)
	}
}

// TestConnUniStream exercises OpenUniStream/AcceptUniStream end to end.
func TestConnUniStream(t *testing.T) {
	client, server := connPair(t, "iroh-uni/0")
	defer client.CloseWithError(0, "")
	defer server.CloseWithError(0, "")

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

	ss, err := client.OpenUniStreamSync(ctx)
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

func clientStableIDCount(e *Endpoint) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.stableIDs)
}

// ExampleConn_Stats prints whether a loopback connection has recorded traffic.
func ExampleConn_Stats() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-stats-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	stats := conn.Stats()
	fmt.Println(stats.BytesSent > 0)
	// Output:
	// true
}

// ExampleConn_Paths prints whether a loopback connection has a selected path.
func ExampleConn_Paths() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-paths-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	for _, path := range conn.Paths() {
		if path.Selected {
			fmt.Println(path.HasAddr, path.Relayed)
			break
		}
	}
	// Output:
	// true false
}

// ExampleConn_WatchPaths prints whether the initial path snapshot is usable.
func ExampleConn_WatchPaths() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-watch-paths-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}
	defer conn.CloseWithError(0, "")

	watch, err := conn.WatchPaths(ctx)
	if err != nil {
		fmt.Println("watch:", err)
		return
	}
	paths := <-watch
	fmt.Println(len(paths) > 0)
	// Output:
	// true
}

// ExampleConn_CloseWithError closes a loopback connection with an application
// code and reads it back from the connection context cause.
func ExampleConn_CloseWithError() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	const alpn = "iroh-close-example/0"
	srvKey, _ := key.GenerateSecretKey()
	server, _ := Bind(ctx, WithSecretKey(srvKey), WithALPNs(alpn),
		WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer server.Shutdown(ctx)
	client, _ := Bind(ctx, WithBindAddr(netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	defer client.Shutdown(ctx)

	go server.Accept(ctx)

	addr := netaddr.NewEndpointAddr(server.ID()).WithIP(server.LocalAddr())
	conn, err := client.Connect(ctx, addr, alpn)
	if err != nil {
		fmt.Println("connect:", err)
		return
	}

	conn.CloseWithError(42, "done")
	<-conn.Context().Done()

	var appErr *quic.ApplicationError
	if errors.As(context.Cause(conn.Context()), &appErr) {
		fmt.Println("close code:", appErr.ErrorCode)
	}
	// Output:
	// close code: 42
}
