package blobs

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// BidiStream is the stream shape used by the blob transfer helpers.
//
// If a stream implements CloseWrite, the helpers use it to close the send side.
// Otherwise Close must close the send side while still allowing reads from the
// peer. This matches iroh.Stream. A net.Conn, whose Close closes both
// directions and which does not implement CloseWrite, is not a suitable
// BidiStream for these helpers.
type BidiStream interface {
	io.Reader
	io.Writer
	Close() error
}

// Store stores raw blobs.
type Store interface {
	GetBlob(Hash) ([]byte, bool)
}

// StoreFunc adapts a function to [Store].
type StoreFunc func(Hash) ([]byte, bool)

// GetBlob calls f(hash).
func (f StoreFunc) GetBlob(hash Hash) ([]byte, bool) { return f(hash) }

// SingleLeafStore stores raw blobs.
//
// Deprecated: use [Store].
type SingleLeafStore = Store

// SingleLeafStoreFunc adapts a function to [SingleLeafStore].
//
// Deprecated: use [StoreFunc].
type SingleLeafStoreFunc = StoreFunc

var (
	// ErrBlobNotFound is returned when a requested blob is not in a store.
	ErrBlobNotFound = errors.New("blobs: blob not found")
	// ErrUnsupportedRequest is returned when a request is outside the
	// raw-blob transfer subset.
	ErrUnsupportedRequest = errors.New("blobs: unsupported request")
)

// ServeBlob serves one full-range raw blob request on s.
//
// The client must send a full [RequestGet] request, then close its send side.
// ServeBlob writes the full-range BAO response, or the hash-sequence root and
// children for [GetAll], and closes its send side.
func ServeBlob(ctx context.Context, s BidiStream, store Store) error {
	return serveBlob(ctx, s, store, EncodeBlob, true)
}

// ServeSingleLeaf serves one single-leaf raw blob request on s.
//
// The client must send a full [RequestGet] / [GetBlob] request, then close its
// send side. ServeSingleLeaf writes the single-leaf BAO response and closes its
// send side. Blobs larger than [MaxSingleLeafSize] are rejected.
func ServeSingleLeaf(ctx context.Context, s BidiStream, store Store) error {
	return serveBlob(ctx, s, store, EncodeSingleLeaf, false)
}

func serveBlob(ctx context.Context, s BidiStream, store Store, encode func([]byte) (Hash, []byte, error), hashSeq bool) error {
	if store == nil {
		return errors.New("blobs: nil blob store")
	}
	requestBytes, err := readAllContext(ctx, s)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: read request: %w", err)
	}
	req, err := DecodeRequestBytes(requestBytes)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: decode request: %w", err)
	}
	switch req.Type {
	case RequestGet:
		if req.Get == nil {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		if !hashSeq && !req.Get.Ranges.IsBlob() {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		if err := writeGet(s, store, *req.Get, encode); err != nil {
			_ = s.Close()
			return err
		}
	case RequestGetMany:
		if req.GetMany == nil {
			_ = s.Close()
			return ErrUnsupportedRequest
		}
		for i, hash := range req.GetMany.Hashes {
			ranges := req.GetMany.Ranges.At(uint64(i))
			if ranges.IsEmpty() {
				continue
			}
			if !ranges.IsAll() {
				_ = s.Close()
				return ErrUnsupportedRequest
			}
			if err := writeBlob(s, store, hash, encode); err != nil {
				_ = s.Close()
				return err
			}
		}
	default:
		_ = s.Close()
		return ErrUnsupportedRequest
	}
	return closeWrite(s)
}

func writeGet(s io.Writer, store Store, req GetRequest, encode func([]byte) (Hash, []byte, error)) error {
	if req.Ranges.IsBlob() {
		return writeBlob(s, store, req.Hash, encode)
	}
	if !req.Ranges.IsAll() {
		return writeBlobRange(s, store, req.Hash, req.Ranges.At(0))
	}
	root, ok := store.GetBlob(req.Hash)
	if !ok {
		return ErrBlobNotFound
	}
	seq, err := ParseHashSequence(root)
	if err != nil {
		return fmt.Errorf("blobs: parse hash sequence: %w", err)
	}
	if err := writeBlobBytes(s, req.Hash, root, encode); err != nil {
		return err
	}
	for _, hash := range seq.hashes {
		if err := writeBlob(s, store, hash, encode); err != nil {
			return err
		}
	}
	return nil
}

func writeBlobRange(s io.Writer, store Store, hash Hash, ranges ChunkRanges) error {
	data, ok := store.GetBlob(hash)
	if !ok {
		return ErrBlobNotFound
	}
	offset, length, ok := singleByteRange(ranges, uint64(len(data)))
	if !ok {
		return ErrUnsupportedRequest
	}
	got, encoded, err := EncodeBlobRange(data, offset, length)
	if err != nil {
		return err
	}
	if got != hash {
		return fmt.Errorf("blobs: stored blob hash mismatch")
	}
	if _, err := s.Write(encoded); err != nil {
		return fmt.Errorf("blobs: write response: %w", err)
	}
	return nil
}

func writeBlob(s io.Writer, store Store, hash Hash, encode func([]byte) (Hash, []byte, error)) error {
	data, ok := store.GetBlob(hash)
	if !ok {
		return ErrBlobNotFound
	}
	return writeBlobBytes(s, hash, data, encode)
}

func writeBlobBytes(s io.Writer, hash Hash, data []byte, encode func([]byte) (Hash, []byte, error)) error {
	got, encoded, err := encode(data)
	if err != nil {
		return err
	}
	if got != hash {
		return fmt.Errorf("blobs: stored blob hash mismatch")
	}
	if _, err := s.Write(encoded); err != nil {
		return fmt.Errorf("blobs: write response: %w", err)
	}
	return nil
}

// GetBlobBytes requests and validates one full-range raw blob from s.
//
// GetBlobBytes sends [GetBlob], closes its send side, reads the response, and
// verifies the returned BAO body against hash.
func GetBlobBytes(ctx context.Context, s BidiStream, hash Hash) ([]byte, error) {
	return getBlob(ctx, s, hash, DecodeBlob)
}

// GetBlobRangeBytes requests and validates a contiguous chunk range from s.
//
// size is the verified full blob size. The returned bytes are the selected
// range, clamped to size.
func GetBlobRangeBytes(ctx context.Context, s BidiStream, hash Hash, ranges ChunkRanges, size uint64) ([]byte, error) {
	offset, length, ok := singleByteRange(ranges, size)
	if !ok {
		return nil, ErrUnsupportedRequest
	}
	if _, err := s.Write(EncodeGetRequestBytes(GetBlobRanges(hash, ranges))); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return nil, fmt.Errorf("blobs: close request: %w", err)
	}
	encoded, err := readAllContext(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("blobs: read response: %w", err)
	}
	data, err := DecodeBlobRange(hash, encoded, offset, length)
	if err != nil {
		return nil, fmt.Errorf("blobs: decode response: %w", err)
	}
	return data, nil
}

// GetManyBlobBytes requests and validates full-range raw blobs from s.
func GetManyBlobBytes(ctx context.Context, s BidiStream, hashes []Hash) ([][]byte, error) {
	hashes = append([]Hash(nil), hashes...)
	if _, err := s.Write(EncodeGetManyRequestBytes(NewGetManyRequest(hashes, ChunkRangesSeqAll()))); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return nil, fmt.Errorf("blobs: close request: %w", err)
	}

	type result struct {
		data [][]byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		data := make([][]byte, 0, len(hashes))
		for _, hash := range hashes {
			b, err := DecodeBlobReader(hash, s)
			if err != nil {
				done <- result{err: fmt.Errorf("blobs: decode response: %w", err)}
				return
			}
			data = append(data, b)
		}
		extra, err := io.ReadAll(s)
		if err != nil {
			done <- result{err: fmt.Errorf("blobs: read response: %w", err)}
			return
		}
		if len(extra) != 0 {
			done <- result{err: fmt.Errorf("%w: trailing %d bytes", ErrInvalidBlob, len(extra))}
			return
		}
		done <- result{data: data}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case res := <-done:
		return res.data, res.err
	case <-ctx.Done():
		_ = s.Close()
		res := <-done
		if res.err != nil {
			return nil, ctx.Err()
		}
		return nil, ctx.Err()
	}
}

// GetHashSequenceBytes requests a hash sequence and all of its child blobs from s.
func GetHashSequenceBytes(ctx context.Context, s BidiStream, root Hash) (HashSequence, [][]byte, error) {
	if _, err := s.Write(EncodeGetRequestBytes(GetAll(root))); err != nil {
		_ = s.Close()
		return HashSequence{}, nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return HashSequence{}, nil, fmt.Errorf("blobs: close request: %w", err)
	}

	type result struct {
		seq  HashSequence
		data [][]byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		rootBytes, err := DecodeBlobReader(root, s)
		if err != nil {
			done <- result{err: fmt.Errorf("blobs: decode response: %w", err)}
			return
		}
		seq, err := ParseHashSequence(rootBytes)
		if err != nil {
			done <- result{err: fmt.Errorf("blobs: parse hash sequence: %w", err)}
			return
		}
		data := make([][]byte, 0, seq.Len())
		for _, hash := range seq.hashes {
			b, err := DecodeBlobReader(hash, s)
			if err != nil {
				done <- result{err: fmt.Errorf("blobs: decode response: %w", err)}
				return
			}
			data = append(data, b)
		}
		extra, err := io.ReadAll(s)
		if err != nil {
			done <- result{err: fmt.Errorf("blobs: read response: %w", err)}
			return
		}
		if len(extra) != 0 {
			done <- result{err: fmt.Errorf("%w: trailing %d bytes", ErrInvalidBlob, len(extra))}
			return
		}
		done <- result{seq: seq, data: data}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case res := <-done:
		return res.seq, res.data, res.err
	case <-ctx.Done():
		_ = s.Close()
		res := <-done
		if res.err != nil {
			return HashSequence{}, nil, ctx.Err()
		}
		return HashSequence{}, nil, ctx.Err()
	}
}

// GetSingleLeaf requests and validates one single-leaf raw blob from s.
//
// GetSingleLeaf sends [GetBlob], closes its send side, reads the response, and
// verifies the returned single-leaf BAO body against hash.
func GetSingleLeaf(ctx context.Context, s BidiStream, hash Hash) ([]byte, error) {
	return getBlob(ctx, s, hash, DecodeSingleLeaf)
}

func getBlob(ctx context.Context, s BidiStream, hash Hash, decode func(Hash, []byte) ([]byte, error)) ([]byte, error) {
	if _, err := s.Write(EncodeGetRequestBytes(GetBlob(hash))); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("blobs: write request: %w", err)
	}
	if err := closeWrite(s); err != nil {
		return nil, fmt.Errorf("blobs: close request: %w", err)
	}
	encoded, err := readAllContext(ctx, s)
	if err != nil {
		return nil, fmt.Errorf("blobs: read response: %w", err)
	}
	data, err := decode(hash, encoded)
	if err != nil {
		return nil, fmt.Errorf("blobs: decode response: %w", err)
	}
	return data, nil
}

func closeWrite(s BidiStream) error {
	if c, ok := s.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return s.Close()
}

func readAllContext(ctx context.Context, r io.ReadCloser) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := io.ReadAll(r)
		done <- result{b: b, err: err}
	}()
	select {
	case res := <-done:
		return res.b, res.err
	case <-ctx.Done():
		_ = r.Close()
		res := <-done
		if res.err != nil {
			return nil, ctx.Err()
		}
		return res.b, ctx.Err()
	}
}

func singleByteRange(ranges ChunkRanges, size uint64) (offset, length uint64, ok bool) {
	ranges = ranges.normalize()
	if ranges.IsEmpty() {
		return 0, 0, true
	}
	if ranges.IsAll() {
		return 0, size, true
	}
	if start, open := ranges.OpenStart(); open {
		if start > maxChunkIndex() {
			return 0, 0, false
		}
		offset = start * ChunkSize
		if offset > size {
			return 0, 0, false
		}
		return offset, size - offset, true
	}
	rs := ranges.Ranges()
	if len(rs) != 1 {
		return 0, 0, false
	}
	if rs[0].Start > maxChunkIndex() || rs[0].End > maxChunkIndex() {
		return 0, 0, false
	}
	offset = rs[0].Start * ChunkSize
	end := rs[0].End * ChunkSize
	if offset > size {
		return 0, 0, false
	}
	if end > size {
		end = size
	}
	if end < offset {
		return 0, 0, false
	}
	return offset, end - offset, true
}

func maxChunkIndex() uint64 {
	return ^uint64(0) / ChunkSize
}
