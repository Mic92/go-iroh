package socket_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
)

// newLoopbackMagic binds a loopback UDP socket and returns a serving MagicConn
// plus a stop func.
func newLoopbackMagic(t *testing.T) (*socket.MagicConn, *net.UDPConn, func()) {
	t.Helper()
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	sock := socket.NewSocket()
	m := socket.NewMagicConn(sock, udp)
	ctx, cancel := context.WithCancel(context.Background())
	go m.Serve(ctx)
	stop := func() {
		cancel()
		m.Close()
	}
	return m, udp, stop
}

// TestMagicConnIPRecvPassThrough checks an IP datagram read through the magic
// socket surfaces the real remote IP unchanged: the IP transport must not rewrite
// the source address into a mapped ULA (iroh/src/socket/transports/ip.rs:219).
func TestMagicConnIPRecvPassThrough(t *testing.T) {
	m, udp, stop := newLoopbackMagic(t)
	defer stop()

	// A second socket sends a datagram to the magic socket's bound port.
	sender, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	const payload = "direct-ip"
	if _, err := sender.WriteTo([]byte(payload), udp.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	m.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, addr, err := m.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Errorf("payload = %q, want %q", buf[:n], payload)
	}

	got, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("addr type = %T, want *net.UDPAddr", addr)
	}
	wantPort := sender.LocalAddr().(*net.UDPAddr).Port
	if got.Port != wantPort {
		t.Errorf("recv addr port = %d, want %d", got.Port, wantPort)
	}
	// The source IP must be a real loopback address, never a mapped ULA.
	if socket.Classify(got.AddrPort().Addr()) != socket.KindIP {
		t.Errorf("recv addr %s classified as mapped, want real IP", got)
	}
}

// TestMagicConnIPSend checks WriteTo to a real IP routes out the IP transport:
// the datagram arrives on a plain UDP socket at the target address.
func TestMagicConnIPSend(t *testing.T) {
	m, _, stop := newLoopbackMagic(t)
	defer stop()

	dst, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	const payload = "out-the-ip-transport"
	n, err := m.WriteTo([]byte(payload), dst.LocalAddr())
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo n = %d, want %d", n, len(payload))
	}

	dst.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	rn, _, err := dst.ReadFrom(buf)
	if err != nil {
		t.Fatalf("dst.ReadFrom: %v", err)
	}
	if string(buf[:rn]) != payload {
		t.Errorf("received %q, want %q", buf[:rn], payload)
	}
}

// TestMagicConnBlackhole checks the blackhole invariant: a WriteTo to a mapped
// address with no live transport (relay/custom/endpoint-id), and a WriteTo after
// Close, both report success so quic-go's loss recovery — not a hard error —
// handles the lost datagram (iroh/src/socket/transports.rs:1176).
func TestMagicConnBlackhole(t *testing.T) {
	m, _, stop := newLoopbackMagic(t)
	defer stop()

	mapped := socket.NewRelayMappedAddr().AddrPort()
	dst := net.UDPAddrFromAddrPort(mapped)
	payload := []byte("relay-not-wired-yet")
	n, err := m.WriteTo(payload, dst)
	if err != nil {
		t.Errorf("WriteTo(mapped) err = %v, want nil (blackhole)", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo(mapped) n = %d, want %d", n, len(payload))
	}

	// After Close, sends are still reported as success.
	stop()
	n, err = m.WriteTo(payload, net.UDPAddrFromAddrPort(
		netip.AddrPortFrom(netip.IPv6Loopback(), 9)))
	if err != nil {
		t.Errorf("WriteTo after close err = %v, want nil (blackhole)", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo after close n = %d, want %d", n, len(payload))
	}
}

// TestMagicConnReadDeadline checks ReadFrom honors a past read deadline by
// returning a timeout net.Error rather than blocking.
func TestMagicConnReadDeadline(t *testing.T) {
	m, _, stop := newLoopbackMagic(t)
	defer stop()

	m.SetReadDeadline(time.Now().Add(-time.Second))
	_, _, err := m.ReadFrom(make([]byte, 16))
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Errorf("ReadFrom past deadline err = %v, want timeout net.Error", err)
	}
}

// TestMagicConnNotOOBCapable pins O1 (DESIGN.md §6): MagicConn deliberately does
// not satisfy quic-go's OOBCapablePacketConn, so quic-go uses its single-packet
// recv/send path. It does expose SyscallConn for buffer sizing and the DF bit,
// which alone does not make it OOB-capable.
func TestMagicConnNotOOBCapable(t *testing.T) {
	m, _, stop := newLoopbackMagic(t)
	defer stop()

	if _, ok := any(m).(quic.OOBCapablePacketConn); ok {
		t.Error("MagicConn satisfies OOBCapablePacketConn; it must not (would enable GSO/GRO that do not generalize across transports)")
	}
	if _, ok := any(m).(net.PacketConn); !ok {
		t.Error("MagicConn must satisfy net.PacketConn")
	}
}

// TestAddrCanonical checks IPAddr canonicalizes an IPv4-mapped IPv6 address back
// to plain IPv4, matching iroh/src/socket/transports.rs:825.
func TestAddrCanonical(t *testing.T) {
	v4mapped := netip.MustParseAddr("::ffff:192.0.2.7")
	a := socket.IPAddr(netip.AddrPortFrom(v4mapped, 443))
	ap, ok := a.IP()
	if !ok {
		t.Fatal("IP() = _, false")
	}
	if !ap.Addr().Is4() {
		t.Errorf("addr = %s, want plain IPv4", ap.Addr())
	}
	if ap.Addr().String() != "192.0.2.7" {
		t.Errorf("addr = %s, want 192.0.2.7", ap.Addr())
	}
}

// TestSocketRelayRoundTrip checks the relay mapped-address table round-trips a
// (url, eid) pair to a stable mapped address and back.
func TestSocketRelayRoundTrip(t *testing.T) {
	s := socket.NewSocket()
	url := base.RelayUrl{}
	eid := base.PublicKey{}

	m1 := s.RelayMappedAddrFor(url, eid)
	m2 := s.RelayMappedAddrFor(url, eid)
	if m1 != m2 {
		t.Error("RelayMappedAddrFor is not stable for the same key")
	}
	if socket.Classify(m1.Addr()) != socket.KindRelay {
		t.Errorf("relay mapped addr %s did not classify as relay", m1.Addr())
	}
	key, ok := s.LookupRelay(m1)
	if !ok || !key.EID.Equal(eid) {
		t.Errorf("LookupRelay = %+v,%v, want eid %s,true", key, ok, eid)
	}
}
