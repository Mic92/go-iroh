//go:build qng_regenerate

// Package quic is internal/qng, a vendored fork of quic-go. This file exists
// only to keep github.com/quic-go/quic-go in the module graph (and thus in the
// module cache) so regenerate.sh can re-fork it; it is never built. See
// README.md.
package quic

import _ "github.com/quic-go/quic-go"
