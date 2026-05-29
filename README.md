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
| `internal/itls` | `iroh/src/tls` | vendored crypto/tls compiles + handshakes; RFC 7250 patch in progress |
| `iroh` (root) | `iroh` | planned (after RFC 7250 TLS) |

## Wire compatibility

Connections to relays, pkarr, and DNS use standard WebPKI TLS and are
wire-compatible with upstream iroh today. The direct peer-to-peer QUIC handshake
uses TLS 1.3 Raw Public Keys (RFC 7250) with **mutual** authentication, which
Go's `crypto/tls` does not support and quic-go drives directly with no pluggable
seam. The approach (see `internal/itls/`): vendor `crypto/tls` out-of-tree
(done — it compiles via small shims for the GOROOT-private dependencies and
completes a TLS 1.3 handshake), patch it for RFC 7250 (in progress), and drive
it from a thin quic-go fork. See `package-spec.md` and `internal/itls/DESIGN.md`.

## License

Dual MIT / Apache-2.0, matching upstream iroh.
