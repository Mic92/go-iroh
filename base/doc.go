// Package base provides the core types shared across go-iroh: cryptographic
// keys, endpoint identifiers and addresses, and relay URLs.
//
// It is a port of the Rust crate iroh-base. The central identity type is the
// Ed25519 [PublicKey], also known as an [EndpointId]: an endpoint is named by,
// and all of its traffic is encrypted for, this key. A [SecretKey] holds the
// private half and can [SecretKey.Sign] messages and recover its [PublicKey].
//
// A [PublicKey] renders as lowercase hex by default ([PublicKey.String]) and
// also has a z-base-32 form ([PublicKey.Z32]) used for pkarr domain names.
//
// An [EndpointAddr] bundles an [EndpointId] with the [TransportAddr] values
// (relay URL, IP socket address, or custom transport) at which it may be
// reached. A [RelayUrl] identifies a relay server.
package base
