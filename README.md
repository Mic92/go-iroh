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
| `dns` | `iroh-dns` | ported, tested (stdlib DNS, DoH, DoT, staggered endpoint lookup) |
| `internal/relayproto` | `iroh-relay/protos` | ported, tested (golden wire snapshots) |
| `internal/relayclient` | `iroh-relay/client` | ported, tested (WS/WSS + X.509, wire-compatible) |
| `internal/relayserver` | `iroh-relay` server | ported, tested (relay datagram forwarding) |
| `relay` | `iroh-relay` (public) | ported, tested |
| `watch` | `n0_watcher` | ported, tested |
| `internal/itls` | `iroh/src/tls` | RFC 7250 raw-public-key TLS ported, tested |
| `internal/qng` | `noq` / quic-go | forked for RFC 7250, multipath, QNT, QAD; tested |
| `iroh` (root) | `iroh` | Endpoint/Conn/Router APIs ported, tested |
| `cmd/iroh-relay` | `iroh-relay` binary | minimal relay server |
| `cmd/iroh-dns-server` | `iroh-dns-server` binary | minimal pkarr HTTP server |

## Wire compatibility

Connections to relays, pkarr, and DNS use standard WebPKI TLS. Direct
peer-to-peer QUIC uses TLS 1.3 Raw Public Keys (RFC 7250) with mutual
authentication. Go's `crypto/tls` does not support RFC 7250, so go-iroh carries
`internal/itls/tls` and drives it from the `internal/qng` quic-go fork.

The main local gates are in `go test ./...`. Live Rust interop gates are opt-in
because they require a checked-out and built Rust iroh tree.

## License

Dual MIT / Apache-2.0, matching upstream iroh.
