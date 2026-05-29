package socket

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Transports multiplexes the magic socket's network paths: a direct-IP
// transport plus an optional relay transport. It is the Go analog of the Rust
// Transports struct (iroh/src/socket/transports.rs:47).
//
// The IP transport is always present. The relay transport is present when the
// endpoint has relays configured; otherwise relay-addressed sends are blackholed
// (reported as success so quic-go's loss recovery retransmits). Custom transport
// routing is recognized and degrades cleanly until a later slice adds it.
type Transports struct {
	ip    *IpTransport
	relay *RelayTransport
	// custom transport is added by a later slice. Its mapped addresses are
	// still recognized by [MagicConn.WriteTo], which blackholes sends to them
	// until the transport exists.
}

// MagicConn is the single net.PacketConn handed to a quic-go Transport. It
// presents every iroh network path — direct IP, relay, custom — as one UDP
// socket, mapping non-IP paths to synthetic IPv6 ULAs so quic-go can address
// them. It is the Go analog of the Rust `impl AsyncUdpSocket for Transport`
// (iroh/src/socket/transports.rs:1067).
//
// MagicConn satisfies net.PacketConn. It deliberately does not satisfy
// quic-go's OOBCapablePacketConn: GSO/GRO/ECN are per-platform UDP-socket
// optimizations that do not generalize across relay and custom transports, so
// quic-go falls back to its single-packet basicConn path (O1 in iroh/DESIGN.md
// §6). Correctness does not depend on them.
//
// Create one with [NewMagicConn] and start it with [MagicConn.Serve]. The zero
// value is not usable.
type MagicConn struct {
	sock       *Socket
	transports *Transports
	udp        *net.UDPConn

	recvCh chan recvBatch

	readDeadline  deadline
	writeDeadline deadline
}

// NewMagicConn returns a MagicConn whose sole transport is an [IpTransport]
// bound to udp. sock holds the mapped-address tables shared with the transports.
// Start the receive loop with [MagicConn.Serve] before handing the MagicConn to
// a quic-go Transport.
func NewMagicConn(sock *Socket, udp *net.UDPConn) *MagicConn {
	return NewMagicConnWithRelay(sock, udp, nil)
}

// NewMagicConnWithRelay returns a MagicConn with an IP transport over udp and,
// if actor is non-nil, a relay transport driven by it. Datagrams received from
// relays surface through [MagicConn.ReadFrom] as a [RelayMappedAddr]; sends to a
// relay mapped address route to the actor. Start the receive loops with
// [MagicConn.Serve].
func NewMagicConnWithRelay(sock *Socket, udp *net.UDPConn, actor *RelayActor) *MagicConn {
	recvCh := make(chan recvBatch, 64)
	transports := &Transports{ip: NewIpTransport(udp, recvCh)}
	if actor != nil {
		transports.relay = NewRelayTransport(sock, actor, recvCh)
	}
	m := &MagicConn{
		sock:       sock,
		transports: transports,
		udp:        udp,
		recvCh:     recvCh,
	}
	m.readDeadline.init()
	m.writeDeadline.init()
	return m
}

// Relay returns the relay transport, or nil if no relay actor was configured.
func (m *MagicConn) Relay() *RelayTransport { return m.transports.relay }

// Serve runs the magic socket's receive loops until ctx is cancelled or the
// underlying socket is closed. It blocks; run it in its own goroutine.
func (m *MagicConn) Serve(ctx context.Context) {
	if m.transports.relay != nil {
		go m.transports.relay.Serve(ctx)
	}
	m.transports.ip.Serve(ctx)
}

// ReadFrom delivers the next datagram from any transport into p, returning its
// length and the net.Addr quic-go should associate with the path it arrived on.
// For IP paths that addr is the real remote IP; for relay and custom paths it is
// the synthetic mapped IPv6 ULA (port 12345). It implements net.PacketConn.
func (m *MagicConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case b := <-m.recvCh:
			addr, ok := m.recvAddr(b.info)
			if !ok {
				// Unknown relay/custom source: cannot present a stable path to
				// quic-go. Drop and keep reading.
				continue
			}
			n := copy(p, b.data)
			return n, addr, nil
		case <-m.readDeadline.wait():
			return 0, nil, timeoutError{}
		}
	}
}

// recvAddr maps a received datagram's RecvInfo to the net.Addr quic-go sees: the
// real IP for an IP path, or the synthetic mapped IPv6 ULA for a relay or custom
// path. It mirrors the Rust recv rewrite in process_datagrams
// (iroh/src/socket.rs:596). Relay and custom datagrams cannot yet be received in
// this build (no relay/custom transport feeds the recv channel); the mapping is
// implemented so the path is correct when those transports land in later slices.
func (m *MagicConn) recvAddr(info RecvInfo) (net.Addr, bool) {
	switch info.Remote.kind {
	case AddrIP:
		ap, _ := info.Remote.IP()
		return net.UDPAddrFromAddrPort(ap), true
	case AddrRelay:
		url, eid, _ := info.Remote.Relay()
		return mappedUDPAddr(m.sock.RelayMappedAddrFor(url, eid).Addr()), true
	case AddrCustom:
		c, _ := info.Remote.Custom()
		return mappedUDPAddr(m.sock.CustomMappedAddrFor(c).Addr()), true
	default:
		return nil, false
	}
}

// mappedUDPAddr wraps a mapped IPv6 ULA as a *net.UDPAddr at the fixed dummy
// port quic-go uses to address the path.
func mappedUDPAddr(a netip.Addr) *net.UDPAddr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(a, mappedPort))
}

// WriteTo routes p to the transport addressed by addr and reports success.
//
// addr is classified by [Classify]: a real IP routes to the IP transport; the
// EndpointId, relay, and custom mapped ULAs route to their transports. A send to
// a path with no live transport, an unknown mapped address, or a closed socket
// is blackholed — WriteTo still returns (len(p), nil). quic-go observes the send
// as successful and its loss recovery retransmits the lost datagram, matching
// the Rust Sender::poll_send blackhole invariant
// (iroh/src/socket/transports.rs:1176).
func (m *MagicConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if m.sock.IsClosed() {
		return len(p), nil
	}
	ap, ok := addrPort(addr)
	if !ok {
		return len(p), nil
	}
	switch Classify(ap.Addr()) {
	case KindIP:
		if _, err := m.transports.ip.send(p, ap); err != nil {
			// Intermittent send errors are treated as a lost datagram, not a
			// fatal socket error (transports.rs:1176).
			return len(p), nil
		}
		return len(p), nil
	case KindRelay:
		if m.transports.relay != nil {
			// A full send queue or unknown relay address is treated as a lost
			// datagram, not an error (transports.rs:1176).
			m.transports.relay.Send(RelayMappedAddr{a: ap.Addr()}, p)
		}
		return len(p), nil
	default:
		// EndpointId / custom paths require machinery of later slices. Until
		// then the datagram is blackholed.
		return len(p), nil
	}
}

// LocalAddr returns the bound local address of the underlying UDP socket. It
// implements net.PacketConn.
func (m *MagicConn) LocalAddr() net.Addr { return m.udp.LocalAddr() }

// Close releases the magic socket. It marks the shared [Socket] closed and
// closes the underlying UDP socket, which ends the receive loop. It implements
// net.PacketConn.
func (m *MagicConn) Close() error {
	m.sock.Close()
	m.readDeadline.set(time.Unix(0, 1))
	return m.udp.Close()
}

// SetDeadline sets both the read and write deadlines. It implements
// net.PacketConn.
func (m *MagicConn) SetDeadline(t time.Time) error {
	m.readDeadline.set(t)
	return m.udp.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future ReadFrom calls. It implements
// net.PacketConn.
func (m *MagicConn) SetReadDeadline(t time.Time) error {
	m.readDeadline.set(t)
	return nil
}

// SetWriteDeadline sets the deadline for future WriteTo calls. Writes go
// straight to the underlying socket, so the deadline is applied there. It
// implements net.PacketConn.
func (m *MagicConn) SetWriteDeadline(t time.Time) error {
	return m.udp.SetWriteDeadline(t)
}

// SyscallConn returns the underlying UDP socket's raw connection. quic-go uses
// it to size the kernel receive buffer and to set the Don't Fragment bit on the
// direct-IP path. Exposing it does not make MagicConn an OOBCapablePacketConn —
// that interface also needs ReadMsgUDP/WriteMsgUDP, which MagicConn does not
// provide — so quic-go still uses its single-packet path (O1, DESIGN.md §6).
func (m *MagicConn) SyscallConn() (syscall.RawConn, error) { return m.udp.SyscallConn() }

// SetReadBuffer sets the kernel receive buffer size on the underlying UDP
// socket. quic-go calls it to raise the buffer to its desired size.
func (m *MagicConn) SetReadBuffer(n int) error { return m.udp.SetReadBuffer(n) }

// SetWriteBuffer sets the kernel send buffer size on the underlying UDP socket.
func (m *MagicConn) SetWriteBuffer(n int) error { return m.udp.SetWriteBuffer(n) }

var _ net.PacketConn = (*MagicConn)(nil)
