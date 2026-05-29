// Package fipsgcm is a shim for crypto/internal/fips140/aes/gcm, providing the
// TLS GCM constructors the vendored crypto/tls uses. With FIPS mode disabled,
// the upstream TLS-nonce wrappers are transparent passthroughs to standard GCM
// (the nonce-prefix-stable / counter-increasing checks are FIPS-gated), so each
// constructor returns a plain cipher.AEAD over the given block.
package fipsgcm

import (
	"crypto/cipher"

	"github.com/tmc/go-iroh/internal/itls/shim/fipsaes"
)

const gcmStandardNonceSize = 12
const gcmTagSize = 16

// NewGCMForTLS12 returns a standard AES-GCM AEAD for TLS 1.2 records.
func NewGCMForTLS12(b *fipsaes.Block) (cipher.AEAD, error) {
	return cipher.NewGCMWithNonceSize(b.Block, gcmStandardNonceSize)
}

// NewGCMForTLS13 returns a standard AES-GCM AEAD for TLS 1.3 records.
func NewGCMForTLS13(b *fipsaes.Block) (cipher.AEAD, error) {
	return cipher.NewGCMWithNonceSize(b.Block, gcmStandardNonceSize)
}
