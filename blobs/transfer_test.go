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

func TestBlobTransfer(t *testing.T) {
	data := vectorData(BlockSize + 1)
	hash := NewHash(data)
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, StoreFunc(func(got Hash) ([]byte, bool) {
			if got != hash {
				t.Errorf("requested hash = %s, want %s", got, hash)
				return nil, false
			}
			return append([]byte(nil), data...), true
		}))
	}()
	got, err := GetBlobBytes(context.Background(), client, hash)
	if err != nil {
		t.Fatalf("GetBlobBytes: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("GetBlobBytes returned %d bytes, want %d", len(got), len(data))
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestGetManyBlobTransfer(t *testing.T) {
	data := [][]byte{
		[]byte("first blob"),
		vectorData(BlockSize + 1),
		[]byte("third blob"),
	}
	var hashes []Hash
	blobs := make(map[Hash][]byte)
	for _, b := range data {
		hash := NewHash(b)
		hashes = append(hashes, hash)
		blobs[hash] = append([]byte(nil), b...)
	}

	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, StoreFunc(func(hash Hash) ([]byte, bool) {
			b, ok := blobs[hash]
			return append([]byte(nil), b...), ok
		}))
	}()
	got, err := GetManyBlobBytes(context.Background(), client, hashes)
	if err != nil {
		t.Fatalf("GetManyBlobBytes: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("GetManyBlobBytes returned %d blobs, want %d", len(got), len(data))
	}
	for i := range data {
		if !bytes.Equal(got[i], data[i]) {
			t.Fatalf("blob %d length = %d, want %d", i, len(got[i]), len(data[i]))
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestGetHashSequenceBytes(t *testing.T) {
	data := [][]byte{
		[]byte("first child"),
		vectorData(BlockSize + 1),
		[]byte("third child"),
	}
	var hashes []Hash
	blobs := make(map[Hash][]byte)
	for _, b := range data {
		hash := NewHash(b)
		hashes = append(hashes, hash)
		blobs[hash] = append([]byte(nil), b...)
	}
	seq := NewHashSequence(hashes)
	root := NewHash(seq.Bytes())
	blobs[root] = seq.Bytes()

	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, StoreFunc(func(hash Hash) ([]byte, bool) {
			b, ok := blobs[hash]
			return append([]byte(nil), b...), ok
		}))
	}()
	gotSeq, got, err := GetHashSequenceBytes(context.Background(), client, root)
	if err != nil {
		t.Fatalf("GetHashSequenceBytes: %v", err)
	}
	if gotSeq.Len() != len(hashes) {
		t.Fatalf("hash seq len = %d, want %d", gotSeq.Len(), len(hashes))
	}
	for i, want := range hashes {
		h, ok := gotSeq.At(i)
		if !ok || h != want {
			t.Fatalf("hash %d = %s, %v, want %s, true", i, h, ok, want)
		}
	}
	if len(got) != len(data) {
		t.Fatalf("GetHashSequenceBytes returned %d blobs, want %d", len(got), len(data))
	}
	for i := range data {
		if !bytes.Equal(got[i], data[i]) {
			t.Fatalf("blob %d length = %d, want %d", i, len(got[i]), len(data[i]))
		}
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
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
