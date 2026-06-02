# internal/itls — RFC 7250 raw-public-key TLS for go-iroh

iroh's direct peer-to-peer QUIC connections authenticate with TLS 1.3 **Raw
Public Keys** (RFC 7250): the ed25519 public key *is* the certificate, with no
X.509 chain. Go's standard `crypto/tls` does not implement RFC 7250, and
quic-go drives `crypto/tls` directly with no pluggable seam. To be
wire-compatible with upstream iroh, go-iroh vendors a patched copy of
`crypto/tls` here and drives it from the qng quic-go fork.

## Layout

- `tls/` — a vendored copy of Go's `crypto/tls`, to be patched for RFC 7250.
  BSD-licensed (see `tls/LICENSE`, the Go Authors' license).
- `shim/` — small replacements for the GOROOT-private packages that `crypto/tls`
  imports and that cannot be imported from outside the standard library:
  - `godebug`, `cpu`, `boring`, `byteorder` — trivial behavioral shims.
  - `fips140tls` — FIPS mode toggle, hardwired to "not required".
  - `hkdf`, `fips140deps_byteorder` — HKDF (RFC 5869) and a byte helper.
  - `fipstls13`, `fipstls12` — the TLS 1.3 / 1.2 key schedules, copied verbatim
    from Go's `crypto/internal/fips140/{tls13,tls12}` with their imports
    repointed at the shims.
  - `fipsaes`, `fipsgcm` — AES-GCM AEAD over stdlib `crypto/aes`/`crypto/cipher`.
    The upstream TLS-nonce GCM wrappers only add FIPS-gated counter enforcement,
    which is a transparent passthrough to standard GCM when FIPS is disabled.

The shims preserve behavior: a standard TLS 1.3 handshake completes and exchanges
encrypted data through the vendored package (see `tls/vendored_smoke_test.go`),
exercising the shimmed key schedule and AEAD.

## Maintenance

To re-sync against a new Go release, re-copy `crypto/tls` and the two FIPS key
schedule files, then re-apply the import rewrites (the `crypto/internal/...` and
`internal/...` imports become `github.com/tmc/go-iroh/internal/itls/shim/...`)
and re-apply the RFC 7250 patch. The shims rarely change.

## When to break this fork

Delete `internal/itls/tls` only when upstream Go `crypto/tls` can handle iroh's
direct peer authentication without local patches. The replacement must provide:

- TLS 1.3 `client_certificate_type` and `server_certificate_type` negotiation
  for RFC 7250 raw public keys,
- QUIC support through `tls.QUICClient` and `tls.QUICServer`,
- parsing of peer certificate messages as DER SubjectPublicKeyInfo instead of
  X.509 chains when raw public keys are negotiated,
- mutual raw-public-key authentication with Ed25519 keys,
- a documented resumption/0-RTT story that does not skip identity verification.

Do not remove this fork merely because `VerifyConnection` exists in stdlib TLS:
without certificate-type negotiation and SPKI parsing, a bare iroh public key
still fails before that callback can establish identity. After any attempted
removal, the root direct-QUIC tests and live Rust interop gates must pass without
importing `internal/itls/tls`.
