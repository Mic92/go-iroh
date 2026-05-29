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
| `dns` | `iroh-dns` | planned |
| `relay` | `iroh-relay` | planned |
| `iroh` (root) | `iroh` | planned |

## License

Dual MIT / Apache-2.0, matching upstream iroh.
