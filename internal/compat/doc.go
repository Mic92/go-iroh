// Package compat holds cross-implementation parity tests comparing go-iroh
// against the reference Rust iroh implementation.
//
// The key-parity tests are gated on cargo being installed and IROH_RUST_REPO
// pointing at a local iroh checkout; they build a small Rust reference binary
// against the local iroh-base crate and diff its output against the go-iroh CLI.
// Live interop probes are additionally gated on GO_IROH_LIVE_RUST_INTEROP=1 and
// existing Rust binaries, and do not build or download Rust code. The package has
// no runtime code.
package compat
