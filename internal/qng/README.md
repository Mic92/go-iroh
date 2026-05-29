# internal/qng — quic-go on RFC 7250 TLS

`qng` ("quic-no-go-tls") is a vendored fork of [quic-go](https://github.com/quic-go/quic-go)
whose only change is that it imports `github.com/tmc/go-iroh/internal/itls/tls`
(the RFC 7250 raw-public-key TLS, see `../itls`) instead of the standard
library's `crypto/tls`.

## Why a fork is necessary

quic-go drives TLS by calling the concrete `crypto/tls` QUIC API
(`tls.QUICClient` / `tls.QUICServer`, added in Go 1.21). There is no seam to
inject a different TLS implementation: the QUIC handshake state machine *is*
`crypto/tls`. iroh's peer-to-peer handshake authenticates with TLS 1.3 raw
public keys (RFC 7250), which `crypto/tls` does not support. So to make Go QUIC
connections wire-compatible with iroh, quic-go must be pointed at the patched TLS.

quic-go's `crypto/tls` use is woven through its `internal/` tree
(`internal/handshake`, `internal/qtls`, `internal/protocol`, `internal/qerr`) as
well as the top-level package. Go's `internal/` visibility rule means a partial
fork is impossible — the whole transitive package set must be copied so the
`tls.Config` / `tls.ConnectionState` types are identical across the graph.

## What the fork changes

Nothing but import paths. Every file is a verbatim copy of the corresponding
quic-go file with two string substitutions:

- `"crypto/tls"` → `tls "github.com/tmc/go-iroh/internal/itls/tls"`
- `"github.com/quic-go/quic-go/..."` → `"github.com/tmc/go-iroh/internal/qng/..."`

The vendored TLS exports the QUIC API with byte-identical signatures, so no
other edits are required.

## Regenerating (on a quic-go bump)

1. Bump the version: `go get github.com/quic-go/quic-go@<version>` and update
   the version string in this file and `regenerate.sh`.
2. Run `./internal/qng/regenerate.sh` from the module root.
3. `go build ./... && go test ./internal/qng/`.

The fork is purely mechanical; the regeneration script reproduces it from the
module cache. Re-review only if quic-go changes how it constructs the
`tls.Config` (e.g. cloning), since RFC 7250 fields must survive `Config.Clone`
— see the `RawPublicKeys` line in `../itls/tls/common.go`.

## Forked version

quic-go **v0.59.1**.
