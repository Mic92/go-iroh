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

// Stream is a bidirectional QUIC stream.
type Stream = quic.Stream

// SendStream is the send half of a unidirectional QUIC stream.
type SendStream = quic.SendStream

// ReceiveStream is the receive half of a unidirectional QUIC stream.
type ReceiveStream = quic.ReceiveStream

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

// ConnectOptions configures [Endpoint.ConnectWith]. It is reserved for future
// pre-handshake controls; the zero value uses the same behavior as [Endpoint.Connect].
type ConnectOptions struct{}

// Connecting is a dialed connection handle returned by [Endpoint.ConnectWith].
// In this build it wraps the qng DialEarly connection returned by [Endpoint.Connect].
type Connecting struct {
	conn *Conn
}

// ServerConfig is reserved for per-connection server TLS options in
// [Incoming.AcceptWith]. The zero value uses the endpoint listener config.
type ServerConfig struct{}

// ALPN returns the negotiated ALPN protocol.
func (c *Connecting) ALPN(context.Context) (string, error) {
	return c.conn.ALPN(), nil
}

// RemoteID returns the target endpoint id.
func (c *Connecting) RemoteID() key.EndpointID {
	return c.conn.RemoteID()
}

// Into0RTT returns the connection and whether 0-RTT was accepted.
func (c *Connecting) Into0RTT() (*Conn, bool) {
	return c.conn, c.conn.Used0RTT()
}

// Connection returns the established connection.
func (c *Connecting) Connection(context.Context) (*Conn, error) {
	return c.conn, nil
}

// IncomingAddr is the transport address of an incoming connection attempt.
type IncomingAddr struct {
	addr net.Addr
}

func newIncomingAddr(addr net.Addr) IncomingAddr { return IncomingAddr{addr: addr} }

// Addr returns the underlying network address.
func (a IncomingAddr) Addr() net.Addr { return a.addr }

// AddrPort returns addr as a UDP address, when it is one.
func (a IncomingAddr) AddrPort() (netip.AddrPort, bool) {
	udp, ok := a.addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return udp.AddrPort(), true
}

// String returns the address string.
func (a IncomingAddr) String() string {
	if a.addr == nil {
		return ""
	}
	return a.addr.String()
}

// LocalTransportAddr is the local transport address an incoming connection
// arrived on.
type LocalTransportAddr struct {
	addr net.Addr
}

func newLocalTransportAddr(addr net.Addr) LocalTransportAddr {
	return LocalTransportAddr{addr: addr}
}

// Addr returns the underlying network address.
func (a LocalTransportAddr) Addr() net.Addr { return a.addr }

// AddrPort returns addr as a UDP address, when it is one.
func (a LocalTransportAddr) AddrPort() (netip.AddrPort, bool) {
	udp, ok := a.addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	return udp.AddrPort(), true
}

// String returns the address string.
func (a LocalTransportAddr) String() string {
	if a.addr == nil {
		return ""
	}
	return a.addr.String()
}

// Incoming is an incoming connection attempt accepted by an [Endpoint]. Call
// Accept to continue the handshake, or Refuse/Ignore to close it.
type Incoming struct {
	ep              *Endpoint
	qc              *quic.Conn
	remote          net.Addr
	remoteValidated bool
	preRetry        *bool
}

// Accept accepts the incoming connection and returns an [Accepting] handle.
func (in *Incoming) Accept() (*Accepting, error) {
	if in == nil || in.qc == nil {
		return nil, errors.New("iroh: nil incoming connection")
	}
	return &Accepting{ep: in.ep, qc: in.qc}, nil
}

// AcceptWith accepts the incoming connection. ServerConfig is reserved for the
// Rust API shape; this build uses the endpoint's listener TLS config.
func (in *Incoming) AcceptWith(*ServerConfig) (*Accepting, error) {
	return in.Accept()
}

// Refuse closes the incoming connection.
func (in *Incoming) Refuse() {
	if in != nil && in.qc != nil {
		in.qc.CloseWithError(0, "refused")
	}
}

// Retry asks the peer to retry this incoming connection. For router filters this
// is evaluated before qng constructs a connection, so it emits a real QUIC Retry
// packet. Calling Retry after AcceptIncoming has returned is too late for QUIC
// Retry and closes the connection.
func (in *Incoming) Retry() error {
	if in != nil && in.preRetry != nil {
		*in.preRetry = true
		return nil
	}
	if in != nil && in.qc != nil {
		in.qc.CloseWithError(0, "retry requested after accept")
	}
	return nil
}

// Ignore closes the incoming connection without waiting for completion.
func (in *Incoming) Ignore() {
	if in != nil && in.qc != nil {
		in.qc.CloseWithError(0, "")
	}
}

// RemoteAddr returns the transport address of the incoming connection.
func (in *Incoming) RemoteAddr() IncomingAddr {
	if in == nil {
		return IncomingAddr{}
	}
	if in.remote != nil {
		return newIncomingAddr(in.remote)
	}
	if in.qc == nil {
		return IncomingAddr{}
	}
	return newIncomingAddr(in.qc.RemoteAddr())
}

// RemoteAddrValidated reports whether qng has validated the remote address.
func (in *Incoming) RemoteAddrValidated() bool {
	if in == nil {
		return false
	}
	if in.preRetry != nil {
		return in.remoteValidated
	}
	if in.qc == nil {
		return false
	}
	return in.qc.RemoteAddrValidated()
}

// LocalAddr returns the local transport address the incoming connection used.
func (in *Incoming) LocalAddr() LocalTransportAddr {
	if in == nil || in.qc == nil {
		return LocalTransportAddr{}
	}
	return newLocalTransportAddr(in.qc.LocalAddr())
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
func (a *Accepting) RemoteAddr() IncomingAddr {
	if a == nil || a.qc == nil {
		return IncomingAddr{}
	}
	return newIncomingAddr(a.qc.RemoteAddr())
}

// Into0RTT returns a connection handle before handshake completion. The peer id
// is not authenticated until [Conn.HandshakeComplete] closes.
func (a *Accepting) Into0RTT() *Conn {
	if a == nil || a.qc == nil {
		return nil
	}
	var stableID uint64
	if a.ep != nil {
		stableID = a.ep.connStableID(a.qc)
	}
	return &Conn{qc: a.qc, side: SideServer, stableID: stableID}
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

// OpenStream opens a new bidirectional stream, blocking until the peer's flow
// control permits it or ctx is done.
func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	return c.qc.OpenStreamSync(ctx)
}

// AcceptStream accepts the next bidirectional stream opened by the peer.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	return c.qc.AcceptStream(ctx)
}

// OpenUniStream opens a new unidirectional (send) stream.
func (c *Conn) OpenUniStream(ctx context.Context) (*SendStream, error) {
	return c.qc.OpenUniStreamSync(ctx)
}

// AcceptUniStream accepts the next unidirectional stream opened by the peer.
func (c *Conn) AcceptUniStream(ctx context.Context) (*ReceiveStream, error) {
	return c.qc.AcceptUniStream(ctx)
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

// Closed returns a channel that is closed when the connection is closed, either
// locally or by the peer. After it fires, [Conn.CloseReason] reports why.
func (c *Conn) Closed() <-chan struct{} { return c.qc.Context().Done() }

// CloseReason returns the error that closed the connection, or nil if it is
// still open. The error is a *[quic.ApplicationError] for an application close
// and a *[quic.TransportError] for a transport close.
func (c *Conn) CloseReason() error {
	select {
	case <-c.qc.Context().Done():
		return context.Cause(c.qc.Context())
	default:
		return nil
	}
}

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
