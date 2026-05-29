# go-iroh

A Go port of [iroh](https://github.com/n0-computer/iroh) — peer-to-peer QUIC
connectivity: direct connections dialed by public key, with hole punching and
relay fallback.

This is a clean-room, idiomatic Go port (a work in progress) built on
[quic-go](https://github.com/quic-go/quic-go) as the QUIC backend. It is not
affiliated with the n0 team.

See `package-spec.md` for the package topology, source mapping, and the
Rust→Go idiom conventions used throughout.

## Status

| Package | Rust crate | Status |
|---|---|---|
| `base` | `iroh-base` | ported, tested |
| `internal/pkarr` | `iroh-dns` (pkarr) | ported, tested |
| `dns` | `iroh-dns` | ported, tested (DoH/DoT, staggered resolution deferred) |
| `internal/relayproto` | `iroh-relay/protos` | ported, tested (golden wire snapshots) |
| `internal/relayclient` | `iroh-relay/client` | ported, tested (WSS + X.509, wire-compatible) |
| `relay` | `iroh-relay` (public) | ported, tested |
| `watch` | `n0_watcher` | ported, tested |
| `iroh` (root) | `iroh` | in progress (needs RFC 7250 P2P TLS) |

## Wire compatibility

Connections to relays, pkarr, and DNS use standard WebPKI TLS and are
wire-compatible with upstream iroh today. The direct peer-to-peer QUIC handshake
uses TLS 1.3 Raw Public Keys (RFC 7250), which Go's `crypto/tls` does not
support; achieving P2P wire compatibility requires a forked `crypto/tls` driven
by quic-go (tracked, in progress). See `package-spec.md`.

## License

Dual MIT / Apache-2.0, matching upstream iroh.
