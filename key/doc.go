// Package key provides Ed25519 endpoint identity keys and signatures for
// go-iroh.
//
// A [SecretKey] signs messages and derives a [PublicKey]. Use [EndpointID] for
// network-facing endpoint identities and PublicKey for cryptographic
// operations. Keys and endpoint IDs render as lowercase hex by default;
// [EndpointID.Z32] returns the z-base-32 form used in pkarr names.
package key
