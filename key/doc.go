// Package key provides Ed25519 endpoint identity types for go-iroh.
//
// A [SecretKey] signs messages and derives a [PublicKey]. A [PublicKey] is
// also an [EndpointId], the stable identifier for an iroh endpoint. Keys render
// as lowercase hex by default; [PublicKey.Z32] returns the z-base-32 form used
// in pkarr names.
package key
