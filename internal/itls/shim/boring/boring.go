// Package boring is a minimal shim for the GOROOT-private crypto/internal/boring.
// BoringCrypto is always disabled here, so the standard Go crypto paths are used.
package boring

import (
	"crypto/cipher"
	"errors"
)

// Enabled reports whether BoringCrypto is in use. Always false in this shim.
const Enabled = false

// Unreachable marks code that should be unreachable when BoringCrypto is
// enabled. It is a no-op here.
func Unreachable() {}

// NewGCMTLS is never called because Enabled is false.
func NewGCMTLS(cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring: disabled")
}

// NewGCMTLS13 is never called because Enabled is false.
func NewGCMTLS13(cipher.Block) (cipher.AEAD, error) {
	return nil, errors.New("boring: disabled")
}
