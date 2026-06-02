// Package iroh provides peer-to-peer QUIC connectivity between endpoints
// identified by ed25519 public keys, interoperable with the Rust iroh project
// (https://github.com/n0-computer/iroh).
//
// An [Endpoint] is the entry point: it binds a UDP socket, holds the endpoint's
// secret key, and dials and accepts QUIC connections authenticated with TLS 1.3
// raw public keys (RFC 7250). A peer is addressed by its [key.EndpointID] plus
// an [netaddr.EndpointAddr] (direct UDP addresses and/or a home relay); the
// connection's transport may be a direct path or a relay.
//
// Connections are [Conn] values wrapping a QUIC connection; streams and
// datagrams follow the quic-go model. The remote peer's verified endpoint id is
// available as [Conn.RemoteID].
//
// ALPN is Application-Layer Protocol Negotiation, the TLS mechanism used by
// QUIC peers to agree on the application protocol carried by a connection.
// go-iroh uses the negotiated ALPN to route incoming connections. ALPN values
// are []byte because iroh treats them as opaque protocol identifiers; printable
// ASCII such as []byte("my/1") is common, but binary values must round-trip too.
//
//	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs([]byte("my/1")))
//	conn, err := ep.Connect(ctx, peerAddr, []byte("my/1"))
//	s, err := conn.OpenStream(ctx)
//
// This package wraps a fork of quic-go (internal/qng) that drives a vendored
// crypto/tls with RFC 7250 support (internal/itls/tls).
package iroh
