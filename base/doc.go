// Package base provides deprecated compatibility aliases for go-iroh's key and
// address packages.
//
// Endpoint identity lives in package key. Endpoint addresses, transport
// addresses, and relay URLs live in package netaddr. This package keeps aliases
// for the old base names so existing users continue to compile while new code
// can import the narrower packages.
package base
