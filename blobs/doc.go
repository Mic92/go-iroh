// Package blobs defines Rust-compatible iroh blob tickets and blob identifiers.
//
// A blob ticket combines a provider endpoint address with a BLAKE3 hash and the
// blob format to request. Its string form is the "blob" kind prefix followed by
// RFC 4648 base32 without padding, matching Rust's iroh-blobs ticket format.
package blobs
