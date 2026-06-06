package iroh

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
	"github.com/tmc/go-iroh/key"
)

// Side reports whether a [Conn] was dialed locally or accepted from a peer.
type Side int

const (
	// SideClient is a connection this endpoint dialed.
	SideClient Side = iota
	// SideServer is a connection this endpoint accepted.
	SideServer
)

func (s Side) String() string {
	switch s {
	case SideClient:
		return "client"
	case SideServer:
		return "server"
	default:
		return "unknown"
	}
}

// Stream is a bidirectional stream.
type Stream struct {
	s *quic.Stream
}

// SendStream is the send half of a unidirectional stream.
type SendStream struct {
	s *quic.SendStream
}

// ReceiveStream is the receive half of a unidirectional stream.
type ReceiveStream struct {
	s *quic.ReceiveStream
}

// Read reads data from s.
func (s *Stream) Read(p []byte) (int, error) { return s.s.Read(p) }

// Write writes data to s.
func (s *Stream) Write(p []byte) (int, error) { return s.s.Write(p) }

// Close closes the send side of s.
func (s *Stream) Close() error { return s.s.Close() }

// SetDeadline sets the read and write deadlines for s.
func (s *Stream) SetDeadline(t time.Time) error { return s.s.SetDeadline(t) }

// SetReadDeadline sets the read deadline for s.
func (s *Stream) SetReadDeadline(t time.Time) error { return s.s.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline for s.
func (s *Stream) SetWriteDeadline(t time.Time) error { return s.s.SetWriteDeadline(t) }

// CancelRead aborts receiving on s with code.
func (s *Stream) CancelRead(code uint64) { s.s.CancelRead(quic.StreamErrorCode(code)) }

// CancelWrite aborts sending on s with code.
func (s *Stream) CancelWrite(code uint64) { s.s.CancelWrite(quic.StreamErrorCode(code)) }

// Context is cancelled when s is closed.
func (s *Stream) Context() context.Context { return s.s.Context() }

// Write writes data to s.
func (s *SendStream) Write(p []byte) (int, error) { return s.s.Write(p) }

// Close closes s.
func (s *SendStream) Close() error { return s.s.Close() }

// SetWriteDeadline sets the write deadline for s.
func (s *SendStream) SetWriteDeadline(t time.Time) error { return s.s.SetWriteDeadline(t) }

// CancelWrite aborts sending on s with code.
func (s *SendStream) CancelWrite(code uint64) { s.s.CancelWrite(quic.StreamErrorCode(code)) }

// Context is cancelled when s is closed.
func (s *SendStream) Context() context.Context { return s.s.Context() }

// Read reads data from s.
func (s *ReceiveStream) Read(p []byte) (int, error) { return s.s.Read(p) }

// SetReadDeadline sets the read deadline for s.
func (s *ReceiveStream) SetReadDeadline(t time.Time) error { return s.s.SetReadDeadline(t) }

// CancelRead aborts receiving on s with code.
func (s *ReceiveStream) CancelRead(code uint64) { s.s.CancelRead(quic.StreamErrorCode(code)) }

// Conn is an established connection to a remote iroh endpoint. The peer's
// identity is authenticated by the RFC 7250 handshake and available via
// [Conn.RemoteID].
type Conn struct {
	qc       *quic.Conn
	remoteID key.EndpointID
	alpn     string
	side     Side
	stableID uint64
}

func newConn(qc *quic.Conn, remoteID key.EndpointID, alpn string, side Side, stableID uint64) (*Conn, error) {
	return &Conn{qc: qc, remoteID: remoteID, alpn: alpn, side: side, stableID: stableID}, nil
}

// Incoming is an incoming connection attempt accepted by an [Endpoint]. Call
// Accept to continue the handshake, or Refuse/Ignore to close it.
type Incoming struct {
	ep     *Endpoint
	qc     *quic.Conn
	remote net.Addr
}

// Accept accepts the incoming connection and returns an [Accepting] handle.
func (in *Incoming) Accept() (*Accepting, error) {
	if in == nil || in.qc == nil {
		return nil, errors.New("iroh: nil incoming connection")
	}
	return &Accepting{ep: in.ep, qc: in.qc}, nil
}

// Refuse closes the incoming connection.
func (in *Incoming) Refuse() {
	if in != nil && in.qc != nil {
		in.qc.CloseWithError(0, "refused")
	}
}

// Ignore closes the incoming connection without waiting for completion.
func (in *Incoming) Ignore() {
	if in != nil && in.qc != nil {
		in.qc.CloseWithError(0, "")
	}
}

// RemoteAddr returns the transport address of the incoming connection.
func (in *Incoming) RemoteAddr() net.Addr {
	if in == nil {
		return nil
	}
	if in.remote != nil {
		return in.remote
	}
	if in.qc == nil {
		return nil
	}
	return in.qc.RemoteAddr()
}

// RemoteAddrValidated reports whether qng has validated the remote address.
func (in *Incoming) RemoteAddrValidated() bool {
	if in == nil {
		return false
	}
	if in.qc == nil {
		return false
	}
	return in.qc.RemoteAddrValidated()
}

// LocalAddr returns the local transport address the incoming connection used.
func (in *Incoming) LocalAddr() net.Addr {
	if in == nil || in.qc == nil {
		return nil
	}
	return in.qc.LocalAddr()
}

// Accepting is an accepted incoming connection whose handshake may still be in
// progress. Call Connection to wait for the verified [Conn].
type Accepting struct {
	ep *Endpoint
	qc *quic.Conn
}

// ALPN waits for the handshake to complete and returns the negotiated ALPN.
func (a *Accepting) ALPN(ctx context.Context) (string, error) {
	if a == nil || a.qc == nil {
		return "", errors.New("iroh: nil accepting connection")
	}
	select {
	case <-a.qc.HandshakeComplete():
	case <-ctx.Done():
		a.qc.CloseWithError(0, "")
		return "", ctx.Err()
	}
	return a.qc.ConnectionState().TLS.NegotiatedProtocol, nil
}

// RemoteAddr returns the transport address of the connection.
func (a *Accepting) RemoteAddr() net.Addr {
	if a == nil || a.qc == nil {
		return nil
	}
	return a.qc.RemoteAddr()
}

// Connection waits for the handshake, verifies the peer id, registers the
// connection with the endpoint, runs handshake hooks, and returns an
// established [Conn].
func (a *Accepting) Connection(ctx context.Context) (*Conn, error) {
	if a == nil || a.qc == nil {
		return nil, errors.New("iroh: nil accepting connection")
	}
	return a.ep.finishAccepting(ctx, a.qc)
}

// RemoteID returns the verified endpoint id of the peer.
func (c *Conn) RemoteID() key.EndpointID { return c.remoteID }

// ALPN returns the negotiated ALPN protocol.
func (c *Conn) ALPN() string { return c.alpn }

// Side reports whether this connection was dialed or accepted.
func (c *Conn) Side() Side { return c.side }

// StableID returns an endpoint-local identifier for this connection. It is
// fixed for the connection lifetime, even when the transport path changes.
func (c *Conn) StableID() uint64 { return c.stableID }

// OpenStreamSync opens a new bidirectional stream, blocking until the peer's
// flow control permits it or ctx is done.
func (c *Conn) OpenStreamSync(ctx context.Context) (*Stream, error) {
	s, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{s: s}, nil
}

// OpenStreamConn opens a bidirectional stream and returns it as a [net.Conn].
func (c *Conn) OpenStreamConn(ctx context.Context) (net.Conn, error) {
	s, err := c.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return streamConn{
		Stream:   s,
		local:    c.LocalAddr(),
		remote:   c.RemoteAddr(),
		remoteID: c.RemoteID(),
		used0RTT: c.Used0RTT(),
	}, nil
}

// AcceptStream accepts the next bidirectional stream opened by the peer.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	s, err := c.qc.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &Stream{s: s}, nil
}

// AcceptStreamConn accepts the next bidirectional stream and returns it as a
// [net.Conn].
func (c *Conn) AcceptStreamConn(ctx context.Context) (net.Conn, error) {
	s, err := c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return streamConn{
		Stream:   s,
		local:    c.LocalAddr(),
		remote:   c.RemoteAddr(),
		remoteID: c.RemoteID(),
		used0RTT: c.Used0RTT(),
	}, nil
}

// OpenUniStreamSync opens a new unidirectional (send) stream.
func (c *Conn) OpenUniStreamSync(ctx context.Context) (*SendStream, error) {
	s, err := c.qc.OpenUniStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &SendStream{s: s}, nil
}

// AcceptUniStream accepts the next unidirectional stream opened by the peer.
func (c *Conn) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	s, err := c.qc.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return &ReceiveStream{s: s}, nil
}

// SendDatagram sends an unreliable datagram.
func (c *Conn) SendDatagram(b []byte) error { return c.qc.SendDatagram(b) }

// ReadDatagram receives the next unreliable datagram.
func (c *Conn) ReadDatagram(ctx context.Context) ([]byte, error) {
	return c.qc.ReceiveDatagram(ctx)
}

// Used0RTT reports whether the connection's early data was sent as 0-RTT and
// accepted by the peer. On the dialing side it is meaningful only after the
// handshake completes (see [Conn.HandshakeComplete]); a value of false means the
// peer rejected 0-RTT and any early data must be resent. It is always false for
// accepted connections that did not resume a prior session.
func (c *Conn) Used0RTT() bool { return c.qc.ConnectionState().Used0RTT }

// MultipathNegotiated reports whether both endpoints negotiated the QUIC
// multipath extension on this connection.
func (c *Conn) MultipathNegotiated() bool {
	return c.qc.ConnectionState().MultipathNegotiated
}

// HandshakeComplete returns a channel closed when the TLS handshake finishes.
// For a 0-RTT dial, [Endpoint.Connect] may return before this fires; waiting on
// it and then checking [Conn.Used0RTT] tells whether the 0-RTT attempt was
// accepted or fell back to a full handshake.
func (c *Conn) HandshakeComplete() <-chan struct{} { return c.qc.HandshakeComplete() }

// Context returns a context that is cancelled when the connection is closed.
func (c *Conn) Context() context.Context { return c.qc.Context() }

// LocalAddr returns the local transport address, if known.
func (c *Conn) LocalAddr() net.Addr { return c.qc.LocalAddr() }

// RemoteAddr returns the remote transport address, if known.
func (c *Conn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

// CloseWithError closes the connection with an application error code and
// reason.
func (c *Conn) CloseWithError(code uint64, reason string) error {
	return c.qc.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

// Close closes the connection with application error code 0 and an empty
// reason. Use [Conn.CloseWithError] to send an application-specific close code.
func (c *Conn) Close() error {
	return c.CloseWithError(0, "")
}

type streamConn struct {
	*Stream
	local    net.Addr
	remote   net.Addr
	remoteID key.EndpointID
	used0RTT bool
}

func (c streamConn) LocalAddr() net.Addr { return c.local }

func (c streamConn) RemoteAddr() net.Addr { return c.remote }

// RemoteID returns the verified endpoint id of the peer that owns the stream.
func (c streamConn) RemoteID() key.EndpointID { return c.remoteID }

// Used0RTT reports whether the parent connection used accepted 0-RTT early
// data. Replay safety is application-specific.
func (c streamConn) Used0RTT() bool { return c.used0RTT }

// connAdapter adapts a qng *quic.Conn to the socket package's
// [socket.Connection] interface so the per-remote state actor can track its
// liveness, RTT, and path without the socket package importing iroh.
type connAdapter struct {
	qc   *quic.Conn
	addr socket.Addr
}

// newConnAdapter wraps qc for the per-remote actor. addr is the connection's
// transport path, classified by the endpoint (a real IP for a direct path, a
// relay address for a relay path).
func newConnAdapter(qc *quic.Conn, addr socket.Addr) *connAdapter {
	return &connAdapter{qc: qc, addr: addr}
}

// SmoothedRTT returns the connection's active-path smoothed RTT. qng negotiates
// multipath, but this adapter still exposes the connection-level active-path RTT
// until per-PathID RTT is surfaced.
func (a *connAdapter) SmoothedRTT() time.Duration { return a.qc.ConnectionStats().SmoothedRTT }

// Done is closed when the connection closes.
func (a *connAdapter) Done() <-chan struct{} { return a.qc.Context().Done() }

// RemoteAddr returns the connection's transport path address.
func (a *connAdapter) RemoteAddr() socket.Addr { return a.addr }

// MultipathNegotiated reports whether qng negotiated the QUIC multipath
// extension on this connection.
func (a *connAdapter) MultipathNegotiated() bool {
	return a.qc.ConnectionState().MultipathNegotiated
}

// Paths returns qng multipath path state for socket observability.
func (a *connAdapter) Paths() []socket.PathInfo {
	qpaths := a.qc.Paths()
	if len(qpaths) == 0 {
		return nil
	}
	paths := make([]socket.PathInfo, len(qpaths))
	for i, p := range qpaths {
		paths[i] = socket.PathInfo{
			ID:        uint32(p.ID),
			Validated: p.Validated,
		}
		if p.HasRTT {
			paths[i].RTT = p.SmoothedRTT
			paths[i].HasRTT = true
		}
		if p.RemoteAddr.IsValid() {
			paths[i].Addr = socket.IPAddr(p.RemoteAddr)
			paths[i].HasAddr = true
		}
	}
	return paths
}

// AddNATTraversalAddress hands one local QNT candidate address to qng.
func (a *connAdapter) AddNATTraversalAddress(addr netip.AddrPort) error {
	err := a.qc.AddNATTraversalAddress(addr)
	if errors.Is(err, quic.ErrNATTraversalNotNegotiated) {
		return socket.ErrExtensionNotNegotiated
	}
	return err
}

// RemoveNATTraversalAddress removes one local QNT candidate address from qng.
func (a *connAdapter) RemoveNATTraversalAddress(addr netip.AddrPort) error {
	err := a.qc.RemoveNATTraversalAddress(addr)
	if errors.Is(err, quic.ErrNATTraversalNotNegotiated) {
		return socket.ErrExtensionNotNegotiated
	}
	return err
}

// InitiateNATTraversalRound asks qng to start one QNT round.
func (a *connAdapter) InitiateNATTraversalRound(ctx context.Context) ([]netip.AddrPort, error) {
	addrs, err := a.qc.InitiateNATTraversalRound(ctx)
	if errors.Is(err, quic.ErrNATTraversalNotNegotiated) {
		return nil, socket.ErrExtensionNotNegotiated
	}
	return addrs, err
}

// NATTraversalAddresses reports the remote QNT candidate set qng has learned.
func (a *connAdapter) NATTraversalAddresses() ([]netip.AddrPort, error) {
	addrs, err := a.qc.NATTraversalAddresses()
	if errors.Is(err, quic.ErrNATTraversalNotNegotiated) {
		return nil, socket.ErrExtensionNotNegotiated
	}
	return addrs, err
}

// OpenPath opens and validates one qng multipath path over the connection's
// existing MagicConn socket.
func (a *connAdapter) OpenPath(ctx context.Context) error {
	for {
		p, err := a.qc.OpenPath(nil)
		if err == nil {
			return p.Validated(ctx)
		}
		if !errors.Is(err, quic.ErrPathLimit) {
			return err
		}
		t := time.NewTimer(10 * time.Millisecond)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return context.Cause(ctx)
		}
	}
}

var _ socket.Connection = (*connAdapter)(nil)
