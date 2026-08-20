package blobs

import (
	"context"
	"testing"
)

func TestLegacyMemStore(t *testing.T) {
	data := []byte("legacy blob")
	store, err := NewBytesMap(data)
	if err != nil {
		t.Fatalf("NewBytesMap: %v", err)
	}
	hash := NewHash(data)

	entry, ok, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || entry.Hash() != hash {
		t.Fatalf("Get = %v, %v, want entry for %v", entry, ok, hash)
	}
	if got := store.Store(); got != store {
		t.Fatalf("Store = %T, want %T", got, store)
	}
	got, ok := store.GetBlob(hash)
	if !ok || string(got) != string(data) {
		t.Fatalf("GetBlob = %q, %v, want %q, true", got, ok, data)
	}
}

func TestLegacyFSStore(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	data := []byte("legacy fs blob")
	hash, err := store.Add(data)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	entry, ok, err := store.Get(context.Background(), hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || entry.Hash() != hash {
		t.Fatalf("Get = %v, %v, want entry for %v", entry, ok, hash)
	}
	got, ok := store.GetBlob(hash)
	if !ok || string(got) != string(data) {
		t.Fatalf("GetBlob = %q, %v, want %q, true", got, ok, data)
	}
}

func TestLegacyStoreFunc(t *testing.T) {
	data := []byte("legacy function blob")
	hash := NewHash(data)
	store := StoreFunc(func(got Hash) ([]byte, bool) {
		return data, got == hash
	})

	blob, err := store.Open(context.Background(), hash)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if blob.Hash() != hash {
		t.Fatalf("Open hash = %v, want %v", blob.Hash(), hash)
	}
}
