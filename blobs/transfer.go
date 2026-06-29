package blobs

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// BidiStream is the stream shape used by the single-leaf transfer helpers.
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
	// single-leaf raw-blob transfer subset.
	ErrUnsupportedRequest = errors.New("blobs: unsupported request")
)

// ServeBlob serves one full-range raw blob request on s.
//
// The client must send a full [RequestGet] / [GetBlob] request, then close its
// send side. ServeBlob writes the full-range BAO response and closes its send
// side.
func ServeBlob(ctx context.Context, s BidiStream, store Store) error {
	return serveBlob(ctx, s, store, EncodeBlob)
}

// ServeSingleLeaf serves one single-leaf raw blob request on s.
//
// The client must send a full [RequestGet] / [GetBlob] request, then close its
// send side. ServeSingleLeaf writes the single-leaf BAO response and closes its
// send side. Blobs larger than [MaxSingleLeafSize] are rejected.
func ServeSingleLeaf(ctx context.Context, s BidiStream, store Store) error {
	return serveBlob(ctx, s, store, EncodeSingleLeaf)
}

func serveBlob(ctx context.Context, s BidiStream, store Store, encode func([]byte) (Hash, []byte, error)) error {
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
	if req.Type != RequestGet || req.Get == nil || !req.Get.Ranges.IsBlob() {
		_ = s.Close()
		return ErrUnsupportedRequest
	}
	data, ok := store.GetBlob(req.Get.Hash)
	if !ok {
		_ = s.Close()
		return ErrBlobNotFound
	}
	hash, encoded, err := encode(data)
	if err != nil {
		_ = s.Close()
		return err
	}
	if hash != req.Get.Hash {
		_ = s.Close()
		return fmt.Errorf("blobs: stored blob hash mismatch")
	}
	if _, err := s.Write(encoded); err != nil {
		_ = s.Close()
		return fmt.Errorf("blobs: write response: %w", err)
	}
	return closeWrite(s)
}

// GetBlobBytes requests and validates one full-range raw blob from s.
//
// GetBlobBytes sends [GetBlob], closes its send side, reads the response, and
// verifies the returned BAO body against hash.
func GetBlobBytes(ctx context.Context, s BidiStream, hash Hash) ([]byte, error) {
	return getBlob(ctx, s, hash, DecodeBlob)
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
