# wasmrelaytest

`wasmrelaytest` is a browser smoke test for the js/wasm relay-only iroh
transport path.

The browser build supports relay-carried QUIC streams. It does not use UDP,
hole punching, local discovery, or mDNS. Browser endpoints should be bound with
relay mode and IP transports disabled:

```go
ep, err := iroh.Bind(ctx,
	iroh.WithRelayMode(relay.ModeCustom(relay.MapFromURLs(relayURL))),
	iroh.WithoutIPTransports(),
)
```

Peers are dialed by endpoint ID plus relay URL:

```go
addr := netaddr.NewEndpointAddr(peerID).WithRelayURL(relayURL)
conn, err := ep.Connect(ctx, addr, alpn)
```

Go's `crypto/rand` works in js/wasm through the browser crypto source; no
Rust-style `getrandom` build flag is needed.

## Verified Browser Surface

The package tests build the wasm binary, serve it with Go's `wasm_exec.js`,
start a hermetic `httptest` relay, and run the page in headless Brave or
Chrome. The covered relay-only cases are:

- browser-to-browser QUIC stream echo with 64KB frames
- browser-to-native QUIC stream echo with 64KB frames
- browser blob fetch from a native provider using `blobs.GetBlobBytes`
- browser gossip publish/receive using `gossip.SubscribeAndJoin` and `Broadcast`
- browser docs sync with a native peer using `docs.Sync` and `docs.Handler`

Build the wasm binary with:

```sh
GOOS=js GOARCH=wasm go build ./cmd/wasmrelaytest
```

Run the browser smoke tests with:

```sh
go test ./cmd/wasmrelaytest -count=1
```

Set `IROH_WASM_BROWSER` to force a browser binary. The test defaults to Brave,
then Chrome, then common Chromium command names.
