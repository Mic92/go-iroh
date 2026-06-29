package blobs

import (
	"context"
	"testing"
)

func TestFSStoreTagsPersist(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("tagged"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.SetTag("keep", RawHash(hash)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}

	reopened, err := NewFSStore(dir)
	if err != nil {
		t.Fatalf("reopen NewFSStore: %v", err)
	}
	value, ok, err := reopened.Tag("keep")
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if !ok || value != RawHash(hash) {
		t.Fatalf("Tag = %+v, %v, want %s", value, ok, hash)
	}
	tags, err := reopened.Tags()
	if err != nil {
		t.Fatalf("Tags: %v", err)
	}
	if len(tags) != 1 || tags[0].Name != "keep" || tags[0].Value != RawHash(hash) {
		t.Fatalf("Tags = %+v", tags)
	}
}

func TestFSStoreGCSweepsUntaggedBlobs(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	keep, err := store.Add([]byte("keep"))
	if err != nil {
		t.Fatalf("Add keep: %v", err)
	}
	drop, err := store.Add([]byte("drop"))
	if err != nil {
		t.Fatalf("Add drop: %v", err)
	}
	if err := store.SetTag("keep", RawHash(keep)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	result, err := store.GC(context.Background())
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if result.Deleted != 1 {
		t.Fatalf("GC deleted %d blobs, want 1", result.Deleted)
	}
	if _, ok := store.GetBlob(keep); !ok {
		t.Fatal("tagged blob was swept")
	}
	if _, ok := store.GetBlob(drop); ok {
		t.Fatal("untagged blob survived GC")
	}
}

func TestFSStoreTempTagProtectsBlob(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	hash, err := store.Add([]byte("temporary"))
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	tag, err := store.NewTempTag(RawHash(hash))
	if err != nil {
		t.Fatalf("NewTempTag: %v", err)
	}
	if _, err := store.GC(context.Background()); err != nil {
		t.Fatalf("GC with temp tag: %v", err)
	}
	if _, ok := store.GetBlob(hash); !ok {
		t.Fatal("temp-tagged blob was swept")
	}
	if err := tag.Close(); err != nil {
		t.Fatalf("Close temp tag: %v", err)
	}
	if _, err := store.GC(context.Background()); err != nil {
		t.Fatalf("GC after temp tag close: %v", err)
	}
	if _, ok := store.GetBlob(hash); ok {
		t.Fatal("blob survived after temp tag close")
	}
}

func TestFSStoreGCMarksHashSeqChildren(t *testing.T) {
	store, err := NewFSStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}
	child, err := store.Add([]byte("child"))
	if err != nil {
		t.Fatalf("Add child: %v", err)
	}
	drop, err := store.Add([]byte("drop"))
	if err != nil {
		t.Fatalf("Add drop: %v", err)
	}
	seq := NewHashSequence([]Hash{child})
	root, err := store.Add(seq.Bytes())
	if err != nil {
		t.Fatalf("Add hash seq: %v", err)
	}
	if err := store.SetTag("collection", HashSeqHash(root)); err != nil {
		t.Fatalf("SetTag: %v", err)
	}
	if _, err := store.GC(context.Background()); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, ok := store.GetBlob(root); !ok {
		t.Fatal("hash seq root was swept")
	}
	if _, ok := store.GetBlob(child); !ok {
		t.Fatal("hash seq child was swept")
	}
	if _, ok := store.GetBlob(drop); ok {
		t.Fatal("untagged blob survived GC")
	}
}
