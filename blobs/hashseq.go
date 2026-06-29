package blobs

import (
	"fmt"
	"slices"
)

// HashSequence is a sequence of blob hashes.
type HashSequence struct {
	hashes []Hash
}

// NewHashSequence returns a hash sequence containing hashes.
func NewHashSequence(hashes []Hash) HashSequence {
	return HashSequence{hashes: slices.Clone(hashes)}
}

// ParseHashSequence parses b as a sequence of 32-byte hashes.
func ParseHashSequence(b []byte) (HashSequence, error) {
	if len(b)%HashSize != 0 {
		return HashSequence{}, fmt.Errorf("blobs: invalid hash sequence length %d", len(b))
	}
	hashes := make([]Hash, 0, len(b)/HashSize)
	for len(b) > 0 {
		var h Hash
		copy(h[:], b[:HashSize])
		hashes = append(hashes, h)
		b = b[HashSize:]
	}
	return HashSequence{hashes: hashes}, nil
}

// Bytes returns seq in the Rust-compatible wire form.
func (seq HashSequence) Bytes() []byte {
	b := make([]byte, 0, len(seq.hashes)*HashSize)
	for _, h := range seq.hashes {
		b = append(b, h[:]...)
	}
	return b
}

// Hashes returns the hashes in seq.
func (seq HashSequence) Hashes() []Hash { return slices.Clone(seq.hashes) }

// Len returns the number of hashes in seq.
func (seq HashSequence) Len() int { return len(seq.hashes) }

// IsEmpty reports whether seq contains no hashes.
func (seq HashSequence) IsEmpty() bool { return len(seq.hashes) == 0 }

// At returns the hash at index i.
func (seq HashSequence) At(i int) (Hash, bool) {
	if i < 0 || i >= len(seq.hashes) {
		return Hash{}, false
	}
	return seq.hashes[i], true
}
