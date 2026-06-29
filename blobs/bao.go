package blobs

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// ChunkSize is the BLAKE3 chunk size used by iroh-blobs.
	ChunkSize = 1024
	// BlockSize is the iroh-blobs BAO block size.
	BlockSize = 16 * ChunkSize
	// MaxSingleLeafSize is the largest payload accepted by the single-leaf
	// BAO helpers.
	MaxSingleLeafSize = BlockSize
)

var (
	// ErrSingleLeafTooLarge is returned when data cannot be represented as a
	// single BAO leaf.
	ErrSingleLeafTooLarge = errors.New("blobs: single leaf too large")
	// ErrInvalidSingleLeaf is returned when a single-leaf BAO response is
	// malformed or fails hash verification.
	ErrInvalidSingleLeaf = errors.New("blobs: invalid single leaf")
)

// EncodeSingleLeaf returns the Rust-compatible full-range BAO response for data.
//
// The single-leaf encoding is valid only for blobs up to one iroh-blobs BAO
// block. The response bytes are an 8-byte little-endian size prefix followed by
// data. The returned hash is the BLAKE3 hash of data.
func EncodeSingleLeaf(data []byte) (Hash, []byte, error) {
	if len(data) > MaxSingleLeafSize {
		return Hash{}, nil, fmt.Errorf("%w: %d > %d", ErrSingleLeafTooLarge, len(data), MaxSingleLeafSize)
	}
	encoded := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint64(encoded[:8], uint64(len(data)))
	copy(encoded[8:], data)
	return NewHash(data), encoded, nil
}

// DecodeSingleLeaf validates and decodes a Rust-compatible single-leaf BAO
// response.
//
// It accepts only full-range responses for blobs up to one iroh-blobs BAO block.
// Larger blobs require parent hashes and the full BAO tree decoder.
func DecodeSingleLeaf(expected Hash, encoded []byte) ([]byte, error) {
	if len(encoded) < 8 {
		return nil, fmt.Errorf("%w: truncated size prefix", ErrInvalidSingleLeaf)
	}
	size := binary.LittleEndian.Uint64(encoded[:8])
	if size > MaxSingleLeafSize {
		return nil, fmt.Errorf("%w: %w: %d > %d", ErrInvalidSingleLeaf, ErrSingleLeafTooLarge, size, MaxSingleLeafSize)
	}
	data := encoded[8:]
	if uint64(len(data)) != size {
		return nil, fmt.Errorf("%w: size prefix %d, payload %d", ErrInvalidSingleLeaf, size, len(data))
	}
	if got := NewHash(data); got != expected {
		return nil, fmt.Errorf("%w: hash mismatch", ErrInvalidSingleLeaf)
	}
	return append([]byte(nil), data...), nil
}
