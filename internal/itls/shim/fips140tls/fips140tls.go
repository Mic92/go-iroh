// Package fips140tls is a shim for crypto/tls/internal/fips140tls. FIPS mode is
// never required in this vendored build, so Required always reports false and
// the standard (non-FIPS) TLS code paths are taken.
package fips140tls

// Required reports whether FIPS 140 mode is required. Always false here.
func Required() bool { return false }

// Force is a no-op in this shim.
func Force() {}

// TestingOnlyAbandon is a no-op in this shim.
func TestingOnlyAbandon() {}
