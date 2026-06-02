// Package base provides endpoint addresses, transport addresses, and relay
// URLs.
//
// It is a port of the address and relay URL parts of the Rust crate iroh-base.
// Endpoint identity lives in package key. This package keeps deprecated aliases
// for key types so existing base.SecretKey and base.EndpointId users continue
// to compile while new code can import the narrower package.
//
// An [EndpointAddr] bundles a key.EndpointId with the [TransportAddr] values
// at which it may be reached. A [RelayUrl] identifies a relay server.
package base
