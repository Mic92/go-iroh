//go:build darwin && arm64

package iroh

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

func TestRDMAStreamTransportLiveDialListen(t *testing.T) {
	requireLiveRDMA(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	client, server, selected := liveRDMAStreamTransports(t, ctx, 120)
	defer client.Close()
	defer server.Close()

	accepted := make(chan StreamAccept, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- server.ListenStreams(ctx, func(a StreamAccept) error {
			accepted <- a
			return nil
		})
	}()

	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "rdma-live/0",
		StableID:    1,
		TransportID: server.ID(),
		Purpose:     "live-test",
		Nonce:       "live",
		Expiry:      time.Now().Add(time.Minute),
	}
	c, err := client.DialStream(ctx, selected.Remote, StreamOptions{Token: tok})
	if err != nil {
		t.Fatalf("dial live rdma stream (%s): %v", rdmaStreamSelectionString(selected), err)
	}
	defer c.Close()
	var s io.ReadWriteCloser
	select {
	case a := <-accepted:
		s = a.Conn
	case err := <-errc:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer s.Close()

	msg := []byte("rdma live")
	done := make(chan error, 1)
	go func() {
		_, err := c.Write(msg)
		done <- err
	}()
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if string(got) != string(msg) {
		t.Fatalf("read = %q, want %q", got, msg)
	}
}

func BenchmarkRDMAStreamTransportLiveThroughput(b *testing.B) {
	requireLiveRDMA(b)
	ctx, cancel := context.WithTimeout(b.Context(), 30*time.Second)
	defer cancel()

	client, server, selected := liveRDMAStreamTransports(b, ctx, 121)
	defer client.Close()
	defer server.Close()

	accepted := make(chan StreamAccept, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- server.ListenStreams(ctx, func(a StreamAccept) error {
			accepted <- a
			return nil
		})
	}()
	tok := StreamOpenToken{
		LocalID:     "client",
		RemoteID:    "server",
		ALPN:        "rdma-live/0",
		StableID:    1,
		TransportID: server.ID(),
		Purpose:     "live-bench",
		Nonce:       "bench",
		Expiry:      time.Now().Add(time.Minute),
	}
	c, err := client.DialStream(ctx, selected.Remote, StreamOptions{Token: tok})
	if err != nil {
		b.Fatalf("dial live rdma stream (%s): %v", rdmaStreamSelectionString(selected), err)
	}
	defer c.Close()
	var s io.ReadWriteCloser
	select {
	case a := <-accepted:
		s = a.Conn
	case err := <-errc:
		b.Fatal(err)
	case <-ctx.Done():
		b.Fatal(ctx.Err())
	}
	defer s.Close()

	buf := make([]byte, 64*1024)
	got := make([]byte, len(buf))
	b.SetBytes(int64(len(buf)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(buf); err != nil {
			b.Fatalf("write rdma stream: %v", err)
		}
		if _, err := io.ReadFull(s, got); err != nil {
			b.Fatalf("read rdma stream: %v", err)
		}
	}
	b.StopTimer()
}

func liveRDMAStreamTransports(tb testing.TB, ctx context.Context, id uint64) (*RDMAStreamTransport, *RDMAStreamTransport, StreamLinkSelection) {
	tb.Helper()
	client, err := NewRDMAStreamTransport(id)
	if err != nil {
		tb.Fatal(err)
	}
	server, err := NewRDMAStreamTransport(id)
	if err != nil {
		client.Close()
		tb.Fatal(err)
	}
	local, err := client.LocalAddrs(ctx)
	if err != nil {
		client.Close()
		server.Close()
		tb.Fatal(err)
	}
	remote, err := server.LocalAddrs(ctx)
	if err != nil {
		client.Close()
		server.Close()
		tb.Fatal(err)
	}
	selected, ok := SelectStreamLink(local, remote)
	if !ok || selected.Class != TransportLinkRDMA {
		client.Close()
		server.Close()
		tb.Fatalf("SelectStreamLink = %+v, %v; want rdma", selected, ok)
	}
	tb.Logf("selected live rdma stream: %s", rdmaStreamSelectionString(selected))
	return client, server, selected
}

func requireLiveRDMA(tb testing.TB) {
	tb.Helper()
	if os.Getenv("GO_IROH_RDMA_ENABLE") != "1" || os.Getenv("GO_IROH_RDMA_LIVE") != "1" {
		tb.Skip("set GO_IROH_RDMA_ENABLE=1 and GO_IROH_RDMA_LIVE=1 to open live RDMA provider")
	}
}
