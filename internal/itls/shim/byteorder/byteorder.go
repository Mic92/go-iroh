// Package byteorder is a minimal shim for the GOROOT-private internal/byteorder,
// providing just the little-endian uint32 reader that the vendored crypto/tls
// uses.
package byteorder

// LEUint32 reads a little-endian uint32 from the first 4 bytes of b.
func LEUint32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
