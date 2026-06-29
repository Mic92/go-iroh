package docs

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStoreSnapshotRoundTrip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	entries := []SignedEntry{
		testSignedEntry(namespace, author, "b", testRecord("b", 1, 2)),
		testSignedEntry(namespace, author, "a", testRecord("a", 1, 1)),
		testSignedEntry(namespace, author, "dir", EmptyRecord(3)),
	}
	for _, entry := range entries {
		store.Put(entry)
	}

	var buf bytes.Buffer
	n, err := store.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != int64(buf.Len()) {
		t.Fatalf("WriteTo bytes = %d, want %d", n, buf.Len())
	}
	var again bytes.Buffer
	if _, err := store.WriteTo(&again); err != nil {
		t.Fatalf("second WriteTo: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), again.Bytes()) {
		t.Fatal("WriteTo is not deterministic")
	}

	loaded := NewMemoryStore()
	rn, err := loaded.ReadFrom(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if rn != int64(buf.Len()) {
		t.Fatalf("ReadFrom bytes = %d, want %d", rn, buf.Len())
	}
	got, want := loaded.Entries(), store.Entries()
	if len(got) != len(want) {
		t.Fatalf("len(loaded) = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if !got[i].Equal(want[i]) {
			t.Fatalf("entry %d = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestMemoryStoreSnapshotMergesByInsertRules(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	old := testSignedEntry(namespace, author, "k", testRecord("old", 1, 1))
	newer := testSignedEntry(namespace, author, "k", testRecord("new", 1, 2))

	src := NewMemoryStore()
	src.Put(old)
	var buf bytes.Buffer
	if _, err := src.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	dst := NewMemoryStore()
	dst.Put(newer)
	if _, err := dst.ReadFrom(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	got, ok := dst.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok || !got.Equal(newer) {
		t.Fatal("ReadFrom replaced newer entry with stale snapshot entry")
	}
}

func TestMemoryStoreSnapshotReadDoesNotNotify(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	src := NewMemoryStore()
	src.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, 1)))

	var buf bytes.Buffer
	if _, err := src.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	dst := NewMemoryStore()
	events, cancel := dst.Subscribe()
	defer cancel()
	if _, err := dst.ReadFrom(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	select {
	case event := <-events:
		t.Fatalf("ReadFrom emitted event %#v", event)
	case <-ctx.Done():
	}
}

func TestMemoryStoreFileRoundTrip(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	store.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, 1)))

	path := filepath.Join(t.TempDir(), "docs.store")
	if err := store.SaveFile(path); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	loaded, err := LoadMemoryStoreFile(path)
	if err != nil {
		t.Fatalf("LoadMemoryStoreFile: %v", err)
	}
	got, ok := loaded.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok {
		t.Fatal("loaded entry missing")
	}
	if want := store.Entries()[0]; !got.Equal(want) {
		t.Fatalf("loaded entry = %#v, want %#v", got, want)
	}
}

func TestMemoryStoreSnapshotErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "bad magic", data: []byte("not a store")},
		{name: "truncated count", data: storeSnapshotMagic},
		{name: "too many entries", data: append(append([]byte(nil), storeSnapshotMagic...), 0xc1, 0x84, 0x3d)},
		{name: "oversized entry", data: append(append([]byte(nil), storeSnapshotMagic...), 1, 0xff, 0xff, 0xff, 0xff, 0x0f)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewMemoryStore().ReadFrom(bytes.NewReader(tt.data)); err == nil {
				t.Fatal("ReadFrom succeeded")
			}
		})
	}
}

func TestMemoryStoreSnapshotWriteError(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()
	store.Put(testSignedEntry(namespace, author, "k", testRecord("one", 1, 1)))

	_, err := store.WriteTo(errorWriter{})
	if err == nil {
		t.Fatal("WriteTo succeeded")
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}
