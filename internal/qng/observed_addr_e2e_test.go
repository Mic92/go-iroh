package quic

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/internal/qng/internal/wire"
)

// This file is the X3 (QUIC Address Discovery) go-to-go capstone, built on the
// same RFC 7250 raw-public-key two-endpoint harness as the multipath e2e test
// (twoEndpoints in multipath_e2e_test.go). It is the only correctness signal
// available without a Rust peer.
//
// The address-discovery wire format and negotiation are pinned against the
// authoritative reference in internal/qng/n0ext/reference/{frame.rs,
// transport_parameters.rs} and the noq-proto source (address_discovery.rs,
// connection/mod.rs). See observed_addr_frame.go / transport_parameters.go.

// TestObservedAddrE2E proves the full QAD round-trip: a server configured to
// send observed-address reports (SendObservedAddressReports, role SendOnly) and
// a client configured to receive them (ReceiveObservedAddressReports, role
// ReceiveOnly) negotiate address discovery; on receiving the client's 1-RTT
// packets the server emits OBSERVED_ADDRESS reporting the client's source
// address; the client records it and surfaces it via Conn.ObservedAddr. The
// reported address must equal the client's real loopback UDP address.
func TestObservedAddrE2E(t *testing.T) {
	serverCfg := &Config{
		SendObservedAddressReports: true,
		// Keep the connection lively so the server keeps sending after the
		// initial exchange, giving its queued OBSERVED_ADDRESS room to flush.
		KeepAlivePeriod: 100 * time.Millisecond,
		MaxIdleTimeout:  10 * time.Second,
	}
	clientCfg := &Config{
		ReceiveObservedAddressReports: true,
		KeepAlivePeriod:               100 * time.Millisecond,
		MaxIdleTimeout:                10 * time.Second,
	}

	clientConn, serverConn, cleanup := twoEndpoints(t, serverCfg, clientCfg)
	defer cleanup()

	// Negotiation: the server reports (SendOnly) to the client (ReceiveOnly), and
	// the client does not report to the server. These mirror the should_report
	// gate (address_discovery.rs:54-56).
	if !serverConn.reportsObservedAddr() {
		t.Fatalf("server reportsObservedAddr() = false, want true")
	}
	if serverConn.acceptsObservedAddr() {
		t.Errorf("server acceptsObservedAddr() = true, want false (client is receive-only)")
	}
	if !clientConn.acceptsObservedAddr() {
		t.Fatalf("client acceptsObservedAddr() = false, want true")
	}
	if clientConn.reportsObservedAddr() {
		t.Errorf("client reportsObservedAddr() = true, want false (client is receive-only)")
	}

	// The client's reflexive address as seen by the server is the client's real
	// UDP local address.
	wantAddr := netip.MustParseAddrPort(clientConn.LocalAddr().String())
	wantAddr = netip.AddrPortFrom(wantAddr.Addr().Unmap(), wantAddr.Port())

	// Poll until the server's OBSERVED_ADDRESS report reaches the client.
	deadline := time.Now().Add(5 * time.Second)
	var got netip.AddrPort
	var ok bool
	for time.Now().Before(deadline) {
		if got, ok = clientConn.ObservedAddr(); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("client never received an observed address")
	}
	if got != wantAddr {
		t.Fatalf("client observed addr = %v, want %v", got, wantAddr)
	}

	// Prove the receiver applies highest seq_no wins on the same negotiated
	// connection: a newer report replaces the current address, and a stale report
	// cannot roll it back.
	newerAddr := netip.MustParseAddrPort("[2001:db8::1]:4433")
	if err := clientConn.handleObservedAddrFrame(&wire.ObservedAddrFrame{
		SeqNo: 100,
		Addr:  newerAddr.Addr(),
		Port:  newerAddr.Port(),
	}); err != nil {
		t.Fatalf("handle newer observed address: %v", err)
	}
	if got, ok = clientConn.ObservedAddr(); !ok || got != newerAddr {
		t.Fatalf("client observed addr after newer seq = %v, %v, want %v, true", got, ok, newerAddr)
	}
	staleAddr := netip.MustParseAddrPort("[2001:db8::2]:4434")
	if err := clientConn.handleObservedAddrFrame(&wire.ObservedAddrFrame{
		SeqNo: 99,
		Addr:  staleAddr.Addr(),
		Port:  staleAddr.Port(),
	}); err != nil {
		t.Fatalf("handle stale observed address: %v", err)
	}
	if got, ok = clientConn.ObservedAddr(); !ok || got != newerAddr {
		t.Fatalf("client observed addr after stale seq = %v, %v, want %v, true", got, ok, newerAddr)
	}

	// The server, being receive-only-incapable here (the client never reports),
	// must surface no observed address.
	if addr, ok := serverConn.ObservedAddr(); ok {
		t.Errorf("server ObservedAddr() = %v, ok=true, want no report", addr)
	}
}

// TestObservedAddrNotNegotiated confirms that without the address-discovery
// transport parameter on either side, no OBSERVED_ADDRESS frame is admitted or
// emitted and Conn.ObservedAddr reports nothing — the un-negotiated default
// stays byte-identical to a plain connection.
func TestObservedAddrNotNegotiated(t *testing.T) {
	clientConn, serverConn, cleanup := twoEndpoints(t, &Config{}, &Config{})
	defer cleanup()

	if clientConn.reportsObservedAddr() || clientConn.acceptsObservedAddr() {
		t.Errorf("client negotiated address discovery with no config")
	}
	if serverConn.reportsObservedAddr() || serverConn.acceptsObservedAddr() {
		t.Errorf("server negotiated address discovery with no config")
	}
	if _, ok := clientConn.ObservedAddr(); ok {
		t.Errorf("client ObservedAddr() ok=true with QAD un-negotiated")
	}
	if _, ok := serverConn.ObservedAddr(); ok {
		t.Errorf("server ObservedAddr() ok=true with QAD un-negotiated")
	}

	// Drive a little time so any (erroneous) frames would have a chance to flow.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	<-ctx.Done()
	if _, ok := clientConn.ObservedAddr(); ok {
		t.Errorf("client ObservedAddr() ok=true after idle with QAD un-negotiated")
	}
}

func TestObservedAddrConfigDefaultsInert(t *testing.T) {
	cfg := populateConfig(nil)
	if cfg.SendObservedAddressReports {
		t.Fatal("default SendObservedAddressReports = true")
	}
	if cfg.ReceiveObservedAddressReports {
		t.Fatal("default ReceiveObservedAddressReports = true")
	}
	if got := addressDiscoveryRole(cfg); got != wire.AddressDiscoveryDisabled {
		t.Fatalf("default addressDiscoveryRole = %v, want Disabled", got)
	}
}

func TestObservedAddrRoleMapping(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want wire.AddressDiscoveryRole
	}{
		{name: "disabled", want: wire.AddressDiscoveryDisabled},
		{name: "send", cfg: Config{SendObservedAddressReports: true}, want: wire.AddressDiscoverySendOnly},
		{name: "receive", cfg: Config{ReceiveObservedAddressReports: true}, want: wire.AddressDiscoveryReceiveOnly},
		{name: "both", cfg: Config{SendObservedAddressReports: true, ReceiveObservedAddressReports: true}, want: wire.AddressDiscoveryBoth},
	}
	for _, tc := range cases {
		if got := addressDiscoveryRole(&tc.cfg); got != tc.want {
			t.Errorf("%s: addressDiscoveryRole = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestObservedAddrStaleSeqNoIgnored(t *testing.T) {
	c := &Conn{
		config: &Config{ReceiveObservedAddressReports: true},
		peerParams: &wire.TransportParameters{
			AddressDiscoveryRole: wire.AddressDiscoverySendOnly,
		},
	}
	if err := c.handleObservedAddrFrame(&wire.ObservedAddrFrame{
		SeqNo: 10,
		Addr:  netip.MustParseAddr("192.0.2.10"),
		Port:  1000,
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleObservedAddrFrame(&wire.ObservedAddrFrame{
		SeqNo: 9,
		Addr:  netip.MustParseAddr("192.0.2.9"),
		Port:  900,
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.handleObservedAddrFrame(&wire.ObservedAddrFrame{
		SeqNo: 10,
		Addr:  netip.MustParseAddr("192.0.2.11"),
		Port:  1100,
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := c.ObservedAddr()
	want := netip.MustParseAddrPort("192.0.2.10:1000")
	if !ok || got != want {
		t.Fatalf("ObservedAddr = %v, %v, want %v, true", got, ok, want)
	}
	if err := c.handleObservedAddrFrame(&wire.ObservedAddrFrame{
		SeqNo: 11,
		Addr:  netip.MustParseAddr("192.0.2.11"),
		Port:  1100,
	}); err != nil {
		t.Fatal(err)
	}
	got, ok = c.ObservedAddr()
	want = netip.MustParseAddrPort("192.0.2.11:1100")
	if !ok || got != want {
		t.Fatalf("ObservedAddr = %v, %v, want %v, true", got, ok, want)
	}
}

func TestObservedAddrQueueReportFromUDPSource(t *testing.T) {
	c := &Conn{
		config: &Config{SendObservedAddressReports: true},
		peerParams: &wire.TransportParameters{
			AddressDiscoveryRole: wire.AddressDiscoveryReceiveOnly,
		},
		framer: newFramer(nil),
	}

	c.maybeQueueObservedAddr(&net.UDPAddr{
		IP:   net.ParseIP("::ffff:192.0.2.10"),
		Port: 1234,
	})
	c.maybeQueueObservedAddr(&net.TCPAddr{
		IP:   net.ParseIP("192.0.2.11"),
		Port: 1235,
	})

	c.framer.controlFrameMutex.Lock()
	defer c.framer.controlFrameMutex.Unlock()
	if len(c.framer.controlFrames) != 1 {
		t.Fatalf("queued frames = %d, want 1", len(c.framer.controlFrames))
	}
	frame, ok := c.framer.controlFrames[0].(*wire.ObservedAddrFrame)
	if !ok {
		t.Fatalf("queued frame = %T, want *wire.ObservedAddrFrame", c.framer.controlFrames[0])
	}
	if frame.SeqNo != 0 || frame.Addr != netip.MustParseAddr("192.0.2.10") || frame.Port != 1234 {
		t.Fatalf("queued frame = %+v, want seq 0 addr 192.0.2.10 port 1234", frame)
	}
	if c.nextObservedAddrSeqNo != 1 {
		t.Fatalf("nextObservedAddrSeqNo = %d, want 1", c.nextObservedAddrSeqNo)
	}
}

func TestObservedAddrConcurrentAccess(t *testing.T) {
	c := &Conn{
		config: &Config{ReceiveObservedAddressReports: true},
		peerParams: &wire.TransportParameters{
			AddressDiscoveryRole: wire.AddressDiscoverySendOnly,
		},
	}
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = c.handleObservedAddrFrame(&wire.ObservedAddrFrame{
				SeqNo: uint64(i),
				Addr:  netip.MustParseAddr("192.0.2.1"),
				Port:  uint16(1000 + i),
			})
		}()
		go func() {
			defer wg.Done()
			_, _ = c.ObservedAddr()
		}()
	}
	wg.Wait()

	got, ok := c.ObservedAddr()
	want := netip.MustParseAddrPort("192.0.2.1:1099")
	if !ok || got != want {
		t.Fatalf("ObservedAddr = %v, %v, want %v, true", got, ok, want)
	}
}
