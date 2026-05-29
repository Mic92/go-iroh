// Package iroh provides peer-to-peer QUIC connectivity between endpoints
// identified by ed25519 public keys, interoperable with the Rust iroh project
// (https://github.com/n0-computer/iroh).
//
// An [Endpoint] is the entry point: it binds a UDP socket, holds the endpoint's
// secret key, and dials and accepts QUIC connections authenticated with TLS 1.3
// raw public keys (RFC 7250). A peer is addressed by its [base.EndpointId] plus
// an [base.EndpointAddr] (direct UDP addresses and/or a home relay); the
// connection's transport may be a direct path or a relay.
//
// Connections are [Conn] values wrapping a QUIC connection; streams and
// datagrams follow the quic-go model. The remote peer's verified endpoint id is
// available as [Conn.RemoteID].
//
//	ep, err := iroh.Bind(ctx, iroh.WithSecretKey(sk), iroh.WithALPNs([]byte("my/1")))
//	conn, err := ep.Connect(ctx, peerAddr, []byte("my/1"))
//	s, err := conn.OpenStream(ctx)
//
// This package wraps a fork of quic-go (internal/qng) that drives a vendored
// crypto/tls with RFC 7250 support (internal/itls/tls). See iroh/DESIGN.md for
// the connectivity-engine design and the wire-compatibility checklist.
package iroh
