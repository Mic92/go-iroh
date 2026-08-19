package blobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"lukechampine.com/blake3/bao"
)

// Store holds blobs addressable by root hash.
//
// Open reports a missing blob as [ErrBlobNotFound]. A Store may also implement
// [Stater] to answer status queries without opening the blob, and [Sink] to
// accept new blobs; callers should use the package-level [Status] and
// [WriteBlob] rather than asserting for those interfaces themselves.
type Store interface {
	Open(ctx context.Context, hash Hash) (Blob, error)
}

// Blob is one stored blob, complete or partial.
type Blob interface {
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

// Stater is an optional [Store] upgrade that reports blob status without
// opening the blob. Use [Status], which falls back to Open.
type Stater interface {
	BlobStatus(Hash) BlobStatus
}

// Sink is an optional [Store] upgrade that accepts new blobs. Use [WriteBlob]
// or [ReadFromBlob], which report a Store that cannot add content.
type Sink interface {
	NewBlob(ctx context.Context) (BlobWriter, error)
}

// BlobWriter accumulates one blob. Write the content, then call Commit to
// store it and learn its root hash.
//
// Close releases the writer's resources. Close after a successful Commit is a
// no-op, so
//
//	w, err := s.NewBlob(ctx)
//	if err != nil {
//		return err
//	}
//	defer w.Close()
//
// is always correct, whether or not Commit is reached. A writer that is closed
// without committing discards its content.
//
// An uncommitted writer has no hash yet, so it cannot be protected by a
// [TempTag]. Implementations must keep in-flight content out of reach of
// [FSStore.GC] by other means; see [FSStore.NewBlob] for how the filesystem
// store does it.
type BlobWriter interface {
	io.Writer
	Commit() (Hash, error)
	Close() error
}

// ReadBlob returns the complete contents of hash from s.
//
// ReadBlob buffers the whole blob in memory. Prefer [Store.Open] and the
// returned [Blob]'s DataReader for blobs of unknown size.
func ReadBlob(ctx context.Context, s Store, hash Hash) ([]byte, error) {
	blob, err := s.Open(ctx, hash)
	if err != nil {
		return nil, err
	}
	defer closeBlob(blob)
	if !blob.IsComplete() {
		return nil, ErrBlobNotFound
	}
	size, verified := blob.Size()
	if !verified {
		return nil, ErrBlobNotFound
	}
	if size > maxInt64 {
		return nil, ErrUnsupportedRequest
	}
	r, err := blob.DataReader(ctx)
	if err != nil {
		return nil, err
	}
	defer closeReaderAt(r)
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil && err != io.EOF {
		return nil, fmt.Errorf("blobs: read data: %w", err)
	}
	return data, nil
}

// WriteBlob stores data in s and returns its root hash.
//
// s must implement [Sink].
func WriteBlob(ctx context.Context, s Store, data []byte) (Hash, error) {
	return ReadFromBlob(ctx, s, bytes.NewReader(data))
}

// ReadFromBlob streams r into s and returns the stored blob's root hash.
//
// s must implement [Sink]. ReadFromBlob does not buffer the whole blob.
func ReadFromBlob(ctx context.Context, s Store, r io.Reader) (Hash, error) {
	sink, ok := s.(Sink)
	if !ok {
		return Hash{}, ErrStoreReadOnly
	}
	w, err := sink.NewBlob(ctx)
	if err != nil {
		return Hash{}, err
	}
	defer w.Close()
	if _, err := io.Copy(w, r); err != nil {
		return Hash{}, err
	}
	return w.Commit()
}

func closeBlob(b Blob) {
	if c, ok := b.(io.Closer); ok {
		_ = c.Close()
	}
}

// MemStore is an in-memory [Store] holding complete raw blobs.
type MemStore struct {
	mu      sync.RWMutex
	entries map[Hash]*MemBlob
}

// NewMemStore returns an in-memory store holding data as complete raw blobs.
func NewMemStore(blobs ...[]byte) (*MemStore, error) {
	m := &MemStore{entries: make(map[Hash]*MemBlob)}
	for _, data := range blobs {
		if _, err := m.Add(data); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// Add stores data as a complete raw blob and returns its hash.
func (m *MemStore) Add(data []byte) (Hash, error) {
	if m == nil {
		return Hash{}, errors.New("blobs: nil store")
	}
	entry, err := NewMemBlob(data)
	if err != nil {
		return Hash{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[Hash]*MemBlob)
	}
	m.entries[entry.hash] = entry
	return entry.hash, nil
}

// Open returns the blob for hash, or [ErrBlobNotFound].
func (m *MemStore) Open(ctx context.Context, hash Hash) (Blob, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, ErrBlobNotFound
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.entries[hash]
	if !ok {
		return nil, ErrBlobNotFound
	}
	return entry, nil
}

// NewBlob returns a writer that stores a blob in memory on Commit.
func (m *MemStore) NewBlob(ctx context.Context) (BlobWriter, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errors.New("blobs: nil store")
	}
	return &memBlobWriter{m: m}, nil
}

type memBlobWriter struct {
	m    *MemStore
	buf  bytes.Buffer
	done bool
}

func (w *memBlobWriter) Write(p []byte) (int, error) {
	if w.done {
		return 0, errors.New("blobs: write after commit")
	}
	return w.buf.Write(p)
}

func (w *memBlobWriter) Commit() (Hash, error) {
	if w.done {
		return Hash{}, errors.New("blobs: commit after commit")
	}
	hash, err := w.m.Add(w.buf.Bytes())
	if err != nil {
		return Hash{}, err
	}
	w.done = true
	w.buf.Reset()
	return hash, nil
}

func (w *memBlobWriter) Close() error {
	w.done = true
	w.buf.Reset()
	return nil
}

// MemBlob is a complete in-memory raw blob.
type MemBlob struct {
	hash     Hash
	data     []byte
	outboard []byte
}

// NewMemBlob returns a complete in-memory raw blob holding data.
func NewMemBlob(data []byte) (*MemBlob, error) {
	outboard, root := bao.EncodeBuf(data, 4, true)
	return &MemBlob{
		hash:     Hash(root),
		data:     append([]byte(nil), data...),
		outboard: outboard,
	}, nil
}

// Hash returns e's root hash.
func (e *MemBlob) Hash() Hash { return e.hash }

// Size returns e's verified data size.
func (e *MemBlob) Size() (uint64, bool) { return uint64(len(e.data)), true }

// IsComplete reports whether e has all data.
func (e *MemBlob) IsComplete() bool { return true }

// DataReader returns an immutable reader for e's data.
func (e *MemBlob) DataReader(ctx context.Context) (io.ReaderAt, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	return bytes.NewReader(e.data), nil
}

// Outboard returns an immutable reader for e's BAO outboard.
func (e *MemBlob) Outboard(ctx context.Context) (Outboard, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	return byteOutboard{Reader: bytes.NewReader(e.outboard), size: int64(len(e.outboard))}, nil
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
