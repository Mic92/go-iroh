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

// SingleLeafStore stores raw blobs that fit in one iroh-blobs BAO block.
type SingleLeafStore interface {
	GetBlob(Hash) ([]byte, bool)
}

// SingleLeafStoreFunc adapts a function to [SingleLeafStore].
type SingleLeafStoreFunc func(Hash) ([]byte, bool)

// GetBlob calls f(hash).
func (f SingleLeafStoreFunc) GetBlob(hash Hash) ([]byte, bool) { return f(hash) }

var (
	// ErrBlobNotFound is returned when a requested blob is not in a store.
	ErrBlobNotFound = errors.New("blobs: blob not found")
	// ErrUnsupportedRequest is returned when a request is outside the
	// single-leaf raw-blob transfer subset.
	ErrUnsupportedRequest = errors.New("blobs: unsupported request")
)

// ServeSingleLeaf serves one single-leaf raw blob request on s.
//
// The client must send a full [RequestGet] / [GetBlob] request, then close its
// send side. ServeSingleLeaf writes the single-leaf BAO response and closes its
// send side. Blobs larger than [MaxSingleLeafSize] are rejected.
func ServeSingleLeaf(ctx context.Context, s BidiStream, store SingleLeafStore) error {
	if store == nil {
		return errors.New("blobs: nil single-leaf store")
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
	hash, encoded, err := EncodeSingleLeaf(data)
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

// GetSingleLeaf requests and validates one single-leaf raw blob from s.
//
// GetSingleLeaf sends [GetBlob], closes its send side, reads the response, and
// verifies the returned single-leaf BAO body against hash.
func GetSingleLeaf(ctx context.Context, s BidiStream, hash Hash) ([]byte, error) {
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
	data, err := DecodeSingleLeaf(hash, encoded)
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
