package blobs

import (
	"bytes"
	"context"
	"errors"
	"io"

	"lukechampine.com/blake3/bao"
)

// Map stores provider-side blob entries addressable by root hash.
type Map interface {
	Get(ctx context.Context, hash Hash) (MapEntry, bool, error)
}

// MapEntry is one provider-side blob entry.
type MapEntry interface {
	Hash() Hash
	Size() (size uint64, verified bool)
	IsComplete() bool
	DataReader(ctx context.Context) (io.ReaderAt, error)
	Outboard(ctx context.Context) (Outboard, error)
}

// Outboard is a BAO outboard reader.
type Outboard interface {
	io.ReaderAt
	Size() int64
}

// BytesMap is an in-memory [Map] for complete raw blobs.
type BytesMap struct {
	entries map[Hash]*BytesEntry
}

// NewBytesMap returns a map containing data as complete raw blobs.
func NewBytesMap(blobs ...[]byte) (*BytesMap, error) {
	m := &BytesMap{entries: make(map[Hash]*BytesEntry)}
	for _, data := range blobs {
		if _, err := m.Add(data); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Add stores data as a complete raw blob and returns its hash.
func (m *BytesMap) Add(data []byte) (Hash, error) {
	if m == nil {
		return Hash{}, errors.New("blobs: nil bytes map")
	}
	entry, err := NewBytesEntry(data)
	if err != nil {
		return Hash{}, err
	}
	if m.entries == nil {
		m.entries = make(map[Hash]*BytesEntry)
	}
	m.entries[entry.hash] = entry
	return entry.hash, nil
}

// Get returns the entry for hash.
func (m *BytesMap) Get(ctx context.Context, hash Hash) (MapEntry, bool, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, false, err
	}
	if m == nil {
		return nil, false, nil
	}
	entry, ok := m.entries[hash]
	return entry, ok, nil
}

// Store returns a [Store] view over m.
func (m *BytesMap) Store() Store {
	return MapStore{Map: m}
}

// BytesEntry is a complete in-memory raw blob entry.
type BytesEntry struct {
	hash     Hash
	data     []byte
	outboard []byte
}

// NewBytesEntry returns a complete in-memory raw blob entry for data.
func NewBytesEntry(data []byte) (*BytesEntry, error) {
	outboard, root := bao.EncodeBuf(data, 4, true)
	return &BytesEntry{
		hash:     Hash(root),
		data:     append([]byte(nil), data...),
		outboard: outboard,
	}, nil
}

// Hash returns e's root hash.
func (e *BytesEntry) Hash() Hash { return e.hash }

// Size returns e's verified data size.
func (e *BytesEntry) Size() (uint64, bool) { return uint64(len(e.data)), true }

// IsComplete reports whether e has all data.
func (e *BytesEntry) IsComplete() bool { return true }

// DataReader returns an immutable reader for e's data.
func (e *BytesEntry) DataReader(ctx context.Context) (io.ReaderAt, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	return bytes.NewReader(e.data), nil
}

// Outboard returns an immutable reader for e's BAO outboard.
func (e *BytesEntry) Outboard(ctx context.Context) (Outboard, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	return byteOutboard{Reader: bytes.NewReader(e.outboard), size: int64(len(e.outboard))}, nil
}

// MapStore adapts a complete raw-blob [Map] to the older [Store] interface.
type MapStore struct {
	Map Map
}

// GetBlob returns the full blob bytes for hash if m contains a complete entry.
func (m MapStore) GetBlob(hash Hash) ([]byte, bool) {
	if m.Map == nil {
		return nil, false
	}
	entry, ok, err := m.Map.Get(context.Background(), hash)
	if err != nil || !ok || !entry.IsComplete() {
		return nil, false
	}
	size, verified := entry.Size()
	if !verified {
		return nil, false
	}
	r, err := entry.DataReader(context.Background())
	if err != nil {
		return nil, false
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil && err != io.EOF {
		return nil, false
	}
	if NewHash(data) != hash {
		return nil, false
	}
	return data, true
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

type byteOutboard struct {
	*bytes.Reader
	size int64
}

func (o byteOutboard) Size() int64 { return o.size }
