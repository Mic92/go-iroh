// Package fipsaes is a shim for crypto/internal/fips140/aes, exposing just the
// Block type and constructor the vendored crypto/tls casts to. It wraps the
// stdlib crypto/aes cipher.
package fipsaes

import (
	"crypto/aes"
	"crypto/cipher"
)

// BlockSize is the AES block size in bytes.
const BlockSize = aes.BlockSize

// Block wraps a stdlib AES cipher.Block.
type Block struct {
	cipher.Block
}

// New wraps a stdlib AES cipher.Block as a *Block.
func New(b cipher.Block) *Block { return &Block{Block: b} }
