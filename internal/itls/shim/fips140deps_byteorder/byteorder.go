// Package byteorder is a minimal shim for crypto/internal/fips140deps/byteorder.
package byteorder

// BEAppendUint16 appends v as big-endian to b.
func BEAppendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
