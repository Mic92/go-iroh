package socket

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// maxDatagramSize bounds a single read from the UDP socket. QUIC packets never
// exceed this; larger reads would be truncated by quic-go anyway.
const maxDatagramSize = 1452 + 512 // generous: max QUIC packet plus headroom

// IpTransport is the direct-UDP transport: it reads datagrams from a
// net.PacketConn and forwards them to the [MagicConn]'s recv channel, and sends
// datagrams the magic socket routes to it. It is the Go analog of the Rust
// IpTransport (iroh/src/socket/transports/ip.rs).
//
// Create one with [NewIpTransport] and start its recv loop with [IpTransport.Serve].
type IpTransport struct {
	conn   net.PacketConn
	recvCh chan<- recvBatch
}

// NewIpTransport returns an IpTransport over conn that delivers received
// datagrams to recvCh. The transport does not take ownership of conn; the caller
// closes it.
func NewIpTransport(conn net.PacketConn, recvCh chan<- recvBatch) *IpTransport {
	return &IpTransport{conn: conn, recvCh: recvCh}
}

// LocalAddr returns the bound local address of the underlying socket.
func (t *IpTransport) LocalAddr() net.Addr { return t.conn.LocalAddr() }

// Serve runs the receive loop until ctx is cancelled or the socket is closed.
// Each datagram is delivered to the recv channel tagged with its real remote IP
// address (canonicalized: an IPv4-mapped IPv6 source becomes plain IPv4, to
// match iroh/src/socket/transports/ip.rs:221 to_canonical). Empty datagrams and
// transient errors are skipped; a closed socket ends the loop cleanly.
func (t *IpTransport) Serve(ctx context.Context) {
	buf := make([]byte, maxDatagramSize)
	for {
		if ctx.Err() != nil {
			return
		}
		n, addr, err := t.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Transient read error (e.g. ICMP-driven recv error on some
			// platforms): keep serving.
			continue
		}
		if n == 0 {
			// Timeout or platform quirk; nothing to deliver.
			continue
		}
		ap, ok := addrPort(addr)
		if !ok {
			continue
		}
		// The transport address is internal to iroh and is always the canonical
		// (unmapped) form. iroh/src/socket/transports/ip.rs:219.
		remote := IPAddr(ap)
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case t.recvCh <- recvBatch{data: data, info: RecvInfo{Remote: remote}}:
		case <-ctx.Done():
			return
		}
	}
}

// send writes p to the IP destination dst. The destination is canonicalized so
// an IPv4-mapped IPv6 address is sent as plain IPv4, matching
// iroh/src/socket/transports/ip.rs:310 canonical_addr. It reports the number of
// bytes written.
func (t *IpTransport) send(p []byte, dst netip.AddrPort) (int, error) {
	canon := netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	return t.conn.WriteTo(p, net.UDPAddrFromAddrPort(canon))
}

// addrPort extracts a netip.AddrPort from a net.Addr, handling the *net.UDPAddr
// that net.PacketConn.ReadFrom returns as well as anything already carrying an
// AddrPort.
func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), true
	case interface{ AddrPort() netip.AddrPort }:
		return v.AddrPort(), true
	default:
		ap, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return netip.AddrPort{}, false
		}
		return ap, true
	}
}
