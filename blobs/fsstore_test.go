package blobs

import (
	"bytes"
	"context"
	"io"
	"testing"

	"lukechampine.com/blake3/bao"
)

func TestFSStorePersistsBlob(t *testing.T) {
	dir := t.TempDir()
	data := bytes.Repeat([]byte("persistent blob"), 2000)

	store, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen NewFSStore: %v", err)
	}
	if got := reopened.BlobStatus(hash); !got.IsComplete() || got.Size != int64(len(data)) {
		t.Fatalf("BlobStatus = %+v, want complete size %d", got, len(data))
	}
	got, ok := reopened.GetBlob(hash)
	if !ok {
		t.Fatal("GetBlob = false, want true")
	}
	if !bytes.Equal(got, data) {
		t.Fatal("GetBlob data mismatch")
	}

	entry, ok, err := reopened.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("Get = false, want true")
	}
	r, err := entry.DataReader(context.Background())
	if err != nil {
		t.Fatalf("DataReader: %v", err)
	}
	buf := make([]byte, len(data))
	if _, err := r.ReadAt(buf, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt data: %v", err)
	}
	if !bytes.Equal(buf, data) {
		t.Fatal("DataReader data mismatch")
	}
	outboard, err := entry.Outboard(context.Background())
	if err != nil {
		t.Fatalf("Outboard: %v", err)
	}
	out := make([]byte, outboard.Size())
	if _, err := outboard.ReadAt(out, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt outboard: %v", err)
	}
	if !bao.VerifyBuf(data, out, 4, hash.Bytes()) {
		t.Fatal("outboard does not verify data")
	}
}

func TestFSStoreServesBlob(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := []byte("serve persistent blob")
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	client, server := newTestBidiStreamPair()
	errc := make(chan error, 1)
	go func() {
		errc <- ServeBlob(context.Background(), server, store)
	}()
	got, err := GetBlobBytes(context.Background(), client, hash)
	if err != nil {
		t.Fatalf("GetBlobBytes: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("transfer = %q, want %q", got, data)
	}
	if err := <-errc; err != nil {
		t.Fatalf("ServeBlob: %v", err)
	}
}

func TestFSStoreHonorsCanceledContext(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("x"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.Get(ctx, hash); err == nil {
		t.Fatal("Get canceled context error = nil")
	}
}
