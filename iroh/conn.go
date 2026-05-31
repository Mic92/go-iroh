package iroh

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
	"github.com/tmc/go-iroh/internal/socket"
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
	remoteID base.EndpointId
	alpn     []byte
	side     Side
}

func newConn(qc *quic.Conn, remoteID base.EndpointId, alpn []byte, side Side) (*Conn, error) {
	return &Conn{qc: qc, remoteID: remoteID, alpn: alpn, side: side}, nil
}

// RemoteID returns the verified endpoint id of the peer.
func (c *Conn) RemoteID() base.EndpointId { return c.remoteID }

// ALPN returns the negotiated ALPN protocol.
func (c *Conn) ALPN() []byte { return c.alpn }

// Side reports whether this connection was dialed or accepted.
func (c *Conn) Side() Side { return c.side }

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

// CloseWithError closes the connection with an application error code and
// reason.
func (c *Conn) CloseWithError(code uint64, reason string) error {
	return c.qc.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

// maxVarInt is the largest value a QUIC variable-length integer can hold
// (2^62-1). Application error codes are encoded as VarInts, so a larger code
// cannot be put on the wire.
const maxVarInt = 1<<62 - 1

// Close closes the connection with an application error code and reason,
// sending a CONNECTION_CLOSE frame to the peer and blocking until the close is
// processed. code must be within the QUIC VarInt range [0, 2^62-1].
func (c *Conn) Close(code uint64, reason []byte) error {
	if code > maxVarInt {
		return fmt.Errorf("close code %d out of QUIC varint range", code)
	}
	return c.qc.CloseWithError(quic.ApplicationErrorCode(code), string(reason))
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

// Paths returns address-free qng multipath path state for socket observability.
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
	}
	return paths
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
