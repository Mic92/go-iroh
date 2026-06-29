// Package http3 adapts iroh connections for HTTP/3 implementations.
//
// The package does not implement HTTP/3. It provides a small QUIC-like surface
// over [iroh.Conn] so higher-level packages can build HTTP/3 over go-iroh
// without importing internal transport packages or adding another QUIC stack.
package http3
