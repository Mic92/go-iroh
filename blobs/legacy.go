package blobs

import (
	"context"
	"errors"
)

// Map is the pre-v0.1 provider interface.
//
// Deprecated: use [Store]. Calls to [Map.Get] need a manual migration because
// an interface method has no implementation body for go fix to inline.
type Map interface {
	Get(ctx context.Context, hash Hash) (MapEntry, bool, error)
}

// MapEntry is the pre-v0.1 name for [Blob].
//
// Deprecated: use [Blob].
//
//go:fix inline
type MapEntry = Blob

// BytesMap is the pre-v0.1 name for [MemStore].
//
// Deprecated: use [MemStore].
//
//go:fix inline
type BytesMap = MemStore

// BytesEntry is the pre-v0.1 name for [MemBlob].
//
// Deprecated: use [MemBlob].
//
//go:fix inline
type BytesEntry = MemBlob

// NewBytesMap returns a [MemStore].
//
// Deprecated: use [NewMemStore].
//
//go:fix inline
func NewBytesMap(data ...[]byte) (*MemStore, error) {
	return NewMemStore(data...)
}

// Get returns a blob using the pre-v0.1 result convention.
//
// Deprecated: use [MemStore.Open].
//
//go:fix inline
func (m *MemStore) Get(ctx context.Context, hash Hash) (Blob, bool, error) {
	blob, err := m.Open(ctx, hash)
	if errors.Is(err, ErrBlobNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return blob, true, nil
}

// Store returns m as a [Store].
//
// Deprecated: pass m directly as a [Store].
//
//go:fix inline
func (m *MemStore) Store() Store { return m }

// GetBlob reads a complete blob using the pre-v0.1 result convention.
//
// Deprecated: use [ReadBlob].
//
//go:fix inline
func (m *MemStore) GetBlob(hash Hash) ([]byte, bool) {
	data, err := ReadBlob(context.Background(), m, hash)
	return data, err == nil
}

// Get returns a blob using the pre-v0.1 result convention.
//
// Deprecated: use [FSStore.Open].
//
//go:fix inline
func (s *FSStore) Get(ctx context.Context, hash Hash) (Blob, bool, error) {
	blob, err := s.Open(ctx, hash)
	if errors.Is(err, ErrBlobNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return blob, true, nil
}

// Store returns s as a [Store].
//
// Deprecated: pass s directly as a [Store].
//
//go:fix inline
func (s *FSStore) Store() Store { return s }

// GetBlob reads a complete blob using the pre-v0.1 result convention.
//
// Deprecated: use [ReadBlob].
//
//go:fix inline
func (s *FSStore) GetBlob(hash Hash) ([]byte, bool) {
	data, err := ReadBlob(context.Background(), s, hash)
	return data, err == nil
}

// MapStore adapts a pre-v0.1 [Map] to [Store].
//
// Deprecated: implement [Store] directly.
type MapStore struct {
	Map Map
}

// Open returns the blob for hash, or [ErrBlobNotFound].
func (m MapStore) Open(ctx context.Context, hash Hash) (Blob, error) {
	if m.Map == nil {
		return nil, ErrBlobNotFound
	}
	blob, ok, err := m.Map.Get(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrBlobNotFound
	}
	return blob, nil
}

// GetBlob reads a complete blob using the pre-v0.1 result convention.
//
// Deprecated: use [ReadBlob].
//
//go:fix inline
func (m MapStore) GetBlob(hash Hash) ([]byte, bool) {
	data, err := ReadBlob(context.Background(), m, hash)
	return data, err == nil
}

// StoreFunc adapts a pre-v0.1 byte-slice provider to [Store].
//
// Deprecated: implement [Store] directly.
type StoreFunc func(Hash) ([]byte, bool)

// Open returns the complete blob for hash, or [ErrBlobNotFound].
func (f StoreFunc) Open(ctx context.Context, hash Hash) (Blob, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, ErrBlobNotFound
	}
	data, ok := f(hash)
	if !ok {
		return nil, ErrBlobNotFound
	}
	return NewMemBlob(data), nil
}

// GetBlob returns the complete blob for hash.
func (f StoreFunc) GetBlob(hash Hash) ([]byte, bool) {
	if f == nil {
		return nil, false
	}
	return f(hash)
}

// SingleLeafStore is the pre-v0.1 name for [Store].
//
// Deprecated: use [Store].
//
//go:fix inline
type SingleLeafStore = Store

// SingleLeafStoreFunc is the pre-v0.1 name for [StoreFunc].
//
// Deprecated: implement [Store] directly.
type SingleLeafStoreFunc = StoreFunc
