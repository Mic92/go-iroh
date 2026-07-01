//go:build js

// Package mdns is unavailable in js/wasm.
//
// Browser endpoints do not have UDP multicast DNS. The package remains
// importable for shared code, but Discovery.Start returns an unsupported error
// and Publish and Resolve are no-ops.
package mdns
