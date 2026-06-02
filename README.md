# go-iroh

`go-iroh` is a Go implementation of the iroh connectivity layer. It provides
peer-to-peer QUIC endpoints identified by ed25519 public keys, with direct
paths, relay fallback, QUIC Retry, multipath, QAD observed addresses, and QNT
NAT traversal support.

The module is a clean-room Go port targeting wire compatibility with upstream
Rust iroh. It is not affiliated with the n0 team.

## Packages

| Package | Purpose |
|---|---|
| `base` | endpoint IDs, keys, endpoint addresses, relay URLs |
| `dns` | pkarr TXT encoding and stdlib/DoH/DoT lookupers |
| `relay` | public relay maps and relay configuration |
| `watch` | small generic watch values |
| `iroh` | Endpoint, Conn, Router, address lookup, metrics |
| `cmd/iroh-relay` | minimal local relay server |
| `cmd/iroh-dns-server` | minimal pkarr HTTP server |

The transport internals live under `internal/`: relay protocol/client/server,
net reports, socket path management, RFC 7250 TLS, and `qng`, the quic-go fork
used for iroh/noq compatibility.

## Install

```sh
go get github.com/tmc/go-iroh
```

This module currently declares Go 1.26 in `go.mod`.

## Use

The `iroh` package is the main entry point:

```go
ep, err := iroh.Bind(ctx, iroh.WithALPNs([]byte("example/1")))
if err != nil {
	return err
}
defer ep.Close(ctx)

conn, err := ep.Connect(ctx, peerAddr, []byte("example/1"))
if err != nil {
	return err
}
defer conn.CloseWithError(0, "")
```

ALPN means Application-Layer Protocol Negotiation. It is the TLS extension that
lets peers agree which application protocol a QUIC connection will carry, such
as `"example/1"` or `"n0/iroh/transfer/example/1"`. go-iroh uses ALPN values to
route incoming connections to handlers.

The API takes ALPN values as `[]byte` because iroh treats protocol names as
opaque byte strings, not necessarily UTF-8 text. Most applications use printable
ASCII and can write `[]byte("example/1")`; using bytes keeps binary protocol
IDs lossless and matches Rust iroh's wire model. Internally, the TLS boundary
converts those bytes to Go strings, which are also byte strings and do not
require UTF-8.

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

For release checks, prefer an isolated build cache:

```sh
GOCACHE=$(mktemp -d /tmp/go-iroh-gocache.XXXXXX) go test -p 1 ./... -count=1
```

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

## Status

The normal local suite covers the public packages, qng transport extensions, and
local relay/direct behavior. The opt-in Rust gates cover live echo, Rust
`transfer` provider/upload, direct-path selection, and qlog evidence for QNT
frames when the host environment provides the required binaries and network
topology.

GOOS=js/GOARCH=wasm builds compile. Browser runtime support is limited by the
platform: the relay WebSocket client has a js-specific dial path, but direct UDP
QUIC, direct paths, and NAT traversal are not available in browser WebAssembly.

## License

Licensed under either Apache-2.0 or MIT, at your option. See [LICENSE](./LICENSE).
