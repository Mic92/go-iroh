package iroh

import (
	"context"

	"github.com/tmc/go-iroh/base"
	quic "github.com/tmc/go-iroh/internal/qng"
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
