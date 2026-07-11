package quic

import (
	"context"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// lossyPacketConn wraps a PacketConn and drops a fraction of outgoing packets
// once dropping is enabled. The drop pattern is deterministic (seeded PRNG) so
// failures reproduce.
type lossyPacketConn struct {
	net.PacketConn
	enabled atomic.Bool
	rate    float64

	mu  sync.Mutex
	rng *mrand.Rand
}

func newLossyPacketConn(pc net.PacketConn, rate float64, seed uint64) *lossyPacketConn {
	return &lossyPacketConn{
		PacketConn: pc,
		rate:       rate,
		rng:        mrand.New(mrand.NewPCG(seed, seed)),
	}
}

func (c *lossyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.enabled.Load() {
		c.mu.Lock()
		drop := c.rng.Float64() < c.rate
		c.mu.Unlock()
		if drop {
			return len(p), nil
		}
	}
	return c.PacketConn.WriteTo(p, addr)
}

// TestMultipathStreamSurvivesLoss is a regression test for the multipath
// stall under packet loss (github.com/tmc/go-iroh issue #1): with multipath
// negotiated, a second path validated, and packets in flight on that path, a
// reliable stream must keep making progress on a lossy link. Before the
// nonzero-path PTO fixes ("qng: drain expired nonzero path PTOs" and
// "qng: preserve PTO stream loss callbacks") an expired path-1 PTO deadline
// spun the loss alarm and stream retransmission stalled, so the transfer below
// never finished.
//
// Loss is enabled only after the handshake and path validation so setup is
// deterministic; both directions then drop ~12% of packets.
func TestMultipathStreamSurvivesLoss(t *testing.T) {
	serverTLS, clientTLS, _, _, _, _ := multipathTLSConfigs(t)

	maxPath := uint32(4)
	serverCfg := &Config{InitialMaxPathID: &maxPath, EnableDatagrams: true}
	clientCfg := &Config{InitialMaxPathID: &maxPath, EnableDatagrams: true}

	serverUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	serverLossy := newLossyPacketConn(serverUDP, 0.12, 1)
	serverTr := &Transport{Conn: serverLossy, ConnectionIDLength: 8}
	defer serverTr.Close()
	ln, err := serverTr.Listen(serverTLS, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	clientLossy := newLossyPacketConn(clientUDP, 0.12, 2)
	clientTr := &Transport{Conn: clientLossy, ConnectionIDLength: 8}
	defer clientTr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	type acceptResult struct {
		conn *Conn
		n    int
		err  error
	}
	serverDone := make(chan acceptResult, 1)
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			serverDone <- acceptResult{err: err}
			return
		}
		str, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- acceptResult{conn: conn, err: err}
			return
		}
		n, err := io.Copy(io.Discard, str)
		serverDone <- acceptResult{conn: conn, n: int(n), err: err}
	}()

	clientConn, err := clientTr.Dial(ctx, ln.Addr(), clientTLS, clientCfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer clientConn.CloseWithError(0, "")

	if !clientConn.multipathNegotiated() {
		t.Fatal("multipath not negotiated")
	}

	// Open and validate a second path, then put real packets in flight on it so
	// path 1 has its own PTO/loss state to (mis)manage under loss.
	path, err := clientConn.OpenPath(nil)
	if err != nil {
		t.Fatalf("OpenPath: %v", err)
	}
	if err := path.Validated(ctx); err != nil {
		t.Fatalf("path 1 never validated: %v", err)
	}
	for range 4 {
		if err := path.SendDatagram([]byte("path-1-traffic")); err != nil {
			t.Fatalf("SendDatagram over path 1: %v", err)
		}
	}

	// Lossy network from here on, in both directions.
	serverLossy.enabled.Store(true)
	clientLossy.enabled.Store(true)

	// Keep path 1 carrying (and losing) packets while the stream transfer runs.
	pathTrafficDone := make(chan struct{})
	go func() {
		defer close(pathTrafficDone)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := path.SendDatagram([]byte("path-1-traffic")); err != nil {
					return
				}
			}
		}
	}()

	const payloadSize = 256 << 10
	str, err := clientConn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, payloadSize)
	if _, err := str.Write(payload); err != nil {
		t.Fatalf("stream write: %v", err)
	}
	str.Close()

	res := <-serverDone
	cancel()
	<-pathTrafficDone
	if res.conn != nil {
		defer res.conn.CloseWithError(0, "")
	}
	if res.err != nil {
		t.Fatalf("server: %v", res.err)
	}
	if res.n != payloadSize {
		t.Fatalf("server received %d bytes, want %d", res.n, payloadSize)
	}
}
