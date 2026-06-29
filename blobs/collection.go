package blobs

import (
	"context"
	"fmt"
	"slices"
	"unicode/utf8"

	"github.com/tmc/go-iroh/endpointticket"
)

const collectionHeader = "CollectionV0."

// CollectionEntry is one named blob in a collection.
//
// Name must be valid UTF-8.
type CollectionEntry struct {
	Name string
	Hash Hash
}

// Collection is a Rust-compatible iroh-blobs collection.
type Collection struct {
	entries []CollectionEntry
}

// NewCollection returns a collection containing entries.
func NewCollection(entries []CollectionEntry) Collection {
	return Collection{entries: slices.Clone(entries)}
}

// Entries returns the collection entries.
func (c Collection) Entries() []CollectionEntry { return slices.Clone(c.entries) }

// Len returns the number of blobs in c.
func (c Collection) Len() int { return len(c.entries) }

// IsEmpty reports whether c contains no blobs.
func (c Collection) IsEmpty() bool { return len(c.entries) == 0 }

// Push appends name and hash to c.
func (c *Collection) Push(name string, hash Hash) {
	c.entries = append(c.entries, CollectionEntry{Name: name, Hash: hash})
}

// MetadataBytes returns the Rust-compatible metadata blob for c.
func (c Collection) MetadataBytes() []byte {
	n := len(collectionHeader) + 10
	for _, entry := range c.entries {
		n += 10 + len(entry.Name)
	}
	b := make([]byte, 0, n)
	b = append(b, collectionHeader...)
	b = appendVarint(b, uint64(len(c.entries)))
	for _, entry := range c.entries {
		name := []byte(entry.Name)
		b = appendVarint(b, uint64(len(name)))
		b = append(b, name...)
	}
	return b
}

// HashSequence returns c's root hash sequence.
func (c Collection) HashSequence() HashSequence {
	hashes := make([]Hash, 0, len(c.entries)+1)
	hashes = append(hashes, NewHash(c.MetadataBytes()))
	for _, entry := range c.entries {
		hashes = append(hashes, entry.Hash)
	}
	return NewHashSequence(hashes)
}

// Root returns the hash of c's root hash sequence.
func (c Collection) Root() Hash { return NewHash(c.HashSequence().Bytes()) }

// ParseCollection parses a collection from a root hash sequence and metadata blob.
func ParseCollection(seq HashSequence, meta []byte) (Collection, error) {
	if seq.IsEmpty() {
		return Collection{}, fmt.Errorf("blobs: empty collection hash sequence")
	}
	metaHash, _ := seq.At(0)
	if got := NewHash(meta); got != metaHash {
		return Collection{}, fmt.Errorf("blobs: collection metadata hash mismatch")
	}
	names, err := parseCollectionNames(meta)
	if err != nil {
		return Collection{}, err
	}
	if len(names)+1 != seq.Len() {
		return Collection{}, fmt.Errorf("blobs: collection names %d, hashes %d", len(names), seq.Len())
	}
	entries := make([]CollectionEntry, 0, len(names))
	for i, name := range names {
		hash, ok := seq.At(i + 1)
		if !ok {
			return Collection{}, fmt.Errorf("blobs: missing collection hash %d", i)
		}
		entries = append(entries, CollectionEntry{Name: name, Hash: hash})
	}
	return Collection{entries: entries}, nil
}

// GetCollectionBytes requests a collection and all of its child blobs from s.
func GetCollectionBytes(ctx context.Context, s BidiStream, root Hash) (Collection, [][]byte, error) {
	seq, blobs, err := GetHashSequenceBytes(ctx, s, root)
	if err != nil {
		return Collection{}, nil, err
	}
	if len(blobs) == 0 {
		return Collection{}, nil, fmt.Errorf("blobs: collection metadata missing")
	}
	c, err := ParseCollection(seq, blobs[0])
	if err != nil {
		return Collection{}, nil, err
	}
	return c, blobs[1:], nil
}

func parseCollectionNames(b []byte) ([]string, error) {
	if len(b) < len(collectionHeader) || string(b[:len(collectionHeader)]) != collectionHeader {
		return nil, fmt.Errorf("blobs: invalid collection header")
	}
	p := parser{b: b[len(collectionHeader):]}
	n, err := p.varint()
	if err != nil {
		return nil, wrapDecodeErr(err)
	}
	if n > uint64(len(p.b)-p.off) {
		return nil, wrapDecodeErr(endpointticket.ErrTruncated)
	}
	var names []string
	for range n {
		size, err := p.varint()
		if err != nil {
			return nil, wrapDecodeErr(err)
		}
		if size > uint64(len(p.b)-p.off) {
			return nil, wrapDecodeErr(endpointticket.ErrTruncated)
		}
		nameBytes := p.b[p.off : p.off+int(size)]
		if !utf8.Valid(nameBytes) {
			return nil, fmt.Errorf("blobs: invalid collection name")
		}
		s := string(nameBytes)
		p.off += int(size)
		names = append(names, s)
	}
	if !p.done() {
		return nil, wrapDecodeErr(endpointticket.ErrTrailingBytes)
	}
	return names, nil
}
