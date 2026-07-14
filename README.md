# go-iroh

`go-iroh` is a Go implementation of iroh. It provides peer-to-peer QUIC
endpoints identified by ed25519 public keys, with direct paths, relay fallback,
QUIC Retry, multipath, QAD observed addresses, and QNT NAT traversal support,
plus Rust-compatible ports of the iroh protocol stack: blobs, gossip, and docs.

The module is a clean-room Go port targeting wire compatibility with upstream
Rust iroh. It is not affiliated with the n0 team.

## Packages

Connectivity layer:

| Package | Purpose |
|---|---|
| `iroh` | Endpoint, Conn, Router, address lookup |
| `key` | endpoint IDs, Ed25519 keys, signatures |
| `netaddr` | endpoint addresses, transport addresses, relay URLs |
| `dns` | pkarr TXT encoding and stdlib/DoH/DoT lookupers |
| `pkarr` | pkarr signed DNS packet codec |
| `relay` | public relay maps and relay configuration |
| `metrics` | small OpenMetrics registry |
| `watch` | small generic watch values |

Protocols (Rust-compatible ports):

| Package | Purpose |
|---|---|
| `blobs` | content-addressed blob tickets, identifiers, and BAO transfer |
| `gossip` | iroh-gossip pub/sub mesh (HyParView membership, PlumTree broadcast) |
| `docs` | iroh-docs multi-writer key-value documents and range sync |
| `endpointticket` | Rust-compatible endpoint ticket codec |
| `postcard` | Rust-compatible postcard wire codec (shared with sibling modules) |
| `http3` | adapts iroh connections for HTTP/3 implementations |

Commands:

| Command | Purpose |
|---|---|
| `cmd/iroh` | utility for iroh identities and addresses (keys, endpoint info) |
| `cmd/iroh-relay` | small, self-hostable relay server |
| `cmd/iroh-dns-server` | pkarr HTTP and DNS server for discovery |
| `cmd/wasmrelaytest` | browser smoke test for the js/wasm relay-only transport |

The transport internals live under `internal/`: relay protocol/client/server,
net reports, socket path management, RFC 7250 TLS, the postcard and pkarr
implementations, the gossip proto state machine, and `qng`, the quic-go fork
used for iroh/noq compatibility.

## Install

```sh
go get github.com/tmc/go-iroh
```

This module currently declares Go 1.26 in `go.mod`.

## Use

The `iroh` package is the main entry point:

```go
ep, err := iroh.Bind(ctx, iroh.WithALPNs("example/1"))
if err != nil {
	return err
}
defer ep.Shutdown(ctx)

conn, err := ep.Connect(ctx, peerAddr, "example/1")
if err != nil {
	return err
}
defer conn.CloseWithError(0, "")
```

ALPN means Application-Layer Protocol Negotiation. It is the TLS extension that
lets peers agree which application protocol a QUIC connection will carry, such
as `"example/1"` or `"n0/iroh/transfer/example/1"`. go-iroh uses ALPN values to
route incoming connections to handlers.

The API takes ALPN values as Go strings. TLS ALPN values are byte strings on the
wire; Go strings preserve arbitrary bytes, while keeping the common printable
ASCII case simple.

See [iroh/example_test.go](./iroh/example_test.go) for runnable direct-loopback
Router and Endpoint examples.

## Wire Compatibility

Relay, pkarr, DoH, and DoT connections use standard WebPKI TLS. Direct
peer-to-peer QUIC uses TLS 1.3 Raw Public Keys (RFC 7250) with mutual endpoint
authentication. Go's standard `crypto/tls` does not support RFC 7250, so this
repository carries `internal/itls/tls` and drives it from `internal/qng`.

`internal/qng` is a quic-go v0.59.1 fork extended for the iroh/noq transport
surface: multipath, QAD observed-address reporting, QNT NAT traversal, and
pre-connection QUIC Retry admission. The fork-local READMEs document when those
forks can be removed.

## Validation

Run the local suite:

```sh
go test ./...
```

For a repeatable local check:

```sh
go test ./... -count=1
```

For loopback stream/datagram latency and throughput, with raw TCP and UDP
baselines:

```sh
GOMAXPROCS=4 go test ./iroh -run '^$' -bench 'Benchmark(Conn|RawTCP|RawUDP)' -benchtime=5s -count=5
```

`BenchmarkRawUDPMagicQueuedPingPong` is the closest raw UDP latency baseline for
the magic-socket path: it uses the same receive queue depth, pooled receive
buffers, caller-buffer copy, and separate write queue shape as the direct IP
transport.

Live Rust interop gates are opt-in because they require a checked-out and built
Rust iroh tree:

```sh
GO_IROH_LIVE_RUST_INTEROP=1 \
IROH_RUST_REPO=/path/to/n0-computer/iroh \
go test ./internal/compat -run 'TestLiveRust' -count=1 -v

GO_IROH_LIVE_RUST_INTEROP=1 \
IROH_RUST_REPO=/path/to/n0-computer/iroh \
go test ./iroh -run TestLiveRustTransferFetchPingDirectPath -count=1 -v
```

The gossip stack has its own opt-in live gate that builds a Rust `iroh-gossip`
helper (from `gossip/testdata/rust-gossip-interop`) and exchanges membership and
broadcast with it over `/iroh-gossip/1`. It requires `cargo`:

```sh
GO_IROH_LIVE_RUST_GOSSIP=1 go test ./gossip -run TestLiveRustGossipInterop -count=1 -v
```

## Status

The connectivity layer is a wire-compatible iroh endpoint. The protocol packages
(`blobs`, `gossip`, `docs`) port the corresponding Rust crates, sharing the
`postcard` and `pkarr` wire codecs; `gossip` carries the full HyParView and
PlumTree state machine with a postcard discovery channel.

The normal local suite covers the public packages, qng transport extensions, and
local relay/direct behavior. The opt-in Rust gates cover live echo, Rust
`transfer` provider/upload, direct-path selection, qlog evidence for QNT frames,
and Go↔Rust gossip membership and broadcast, when the host environment provides
the required binaries and network topology.

GOOS=js/GOARCH=wasm builds compile. Browser runtime support is limited by the
platform: the relay WebSocket client has a js-specific dial path, but direct UDP
QUIC, direct paths, and NAT traversal are not available in browser WebAssembly.

## License

go-iroh is licensed under the MIT License. See [LICENSE](./LICENSE).

The forked quic-go code under `internal/qng` retains its upstream license notice
in `internal/qng/LICENSE`.
