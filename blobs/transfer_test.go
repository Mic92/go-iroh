package blobs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestSingleLeafTransfer(t *testing.T) {
	data := []byte("hello single leaf")
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeSingleLeaf(context.Background(), server, SingleLeafStoreFunc(func(got Hash) ([]byte, bool) {
			if got != hash {
				t.Errorf("requested hash = %s, want %s", got, hash)
				return nil, false
			}
			return append([]byte(nil), data...), true
		}))
	}()
	got, err := GetSingleLeaf(context.Background(), client, hash)
	if err != nil {
		t.Fatalf("GetSingleLeaf: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("GetSingleLeaf = %q, want %q", got, data)
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeSingleLeaf: %v", err)
	}
}

func TestServeSingleLeafErrors(t *testing.T) {
	hash := NewHash([]byte("missing"))
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeSingleLeaf(context.Background(), server, SingleLeafStoreFunc(func(Hash) ([]byte, bool) {
			return nil, false
		}))
	}()
	if _, err := client.Write(EncodeGetRequestBytes(GetBlob(hash))); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("ServeSingleLeaf missing error = %v, want %v", err, ErrBlobNotFound)
	}

	client, server = newTestBidiStreamPair()
	errc = make(chan error, 1)
	go func() {
		errc <- ServeSingleLeaf(context.Background(), server, SingleLeafStoreFunc(func(Hash) ([]byte, bool) {
			return nil, false
		}))
	}()
	if _, err := client.Write(EncodeGetRequestBytes(GetAll(hash))); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, ErrUnsupportedRequest) {
		t.Fatalf("ServeSingleLeaf unsupported error = %v, want %v", err, ErrUnsupportedRequest)
	}
}

func TestGetSingleLeafValidation(t *testing.T) {
	hash := NewHash([]byte("expected"))
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		_, _ = io.ReadAll(server)
		_, err := server.Write([]byte{1, 2, 3})
		if closeErr := server.Close(); err == nil {
			err = closeErr
		}
		errc <- err
	}()
	_, err := GetSingleLeaf(context.Background(), client, hash)
	if !errors.Is(err, ErrInvalidSingleLeaf) {
		t.Fatalf("GetSingleLeaf validation error = %v, want %v", err, ErrInvalidSingleLeaf)
	}
	if err := <-errc; err != nil {
		t.Fatalf("server write: %v", err)
	}
}

type testBidiStream struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newTestBidiStreamPair() (*testBidiStream, *testBidiStream) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()
	return &testBidiStream{r: br, w: aw}, &testBidiStream{r: ar, w: bw}
}

func (s *testBidiStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s *testBidiStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s *testBidiStream) Close() error                { return s.w.Close() }
func (s *testBidiStream) CloseWrite() error           { return s.w.Close() }
