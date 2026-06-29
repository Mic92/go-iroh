package docs

import (
	"testing"

	"github.com/tmc/go-iroh/blobs"
)

func TestMemoryStorePut(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()

	first := testSignedEntry(namespace, author, "k", testRecord("one", 1, 1))
	if got := store.Put(first); !got.Inserted() || got.Removed() != 0 {
		t.Fatalf("Put(first) = inserted %v removed %d, want true 0", got.Inserted(), got.Removed())
	}
	older := testSignedEntry(namespace, author, "k", testRecord("old", 1, 0))
	if got := store.Put(older); got.Inserted() || got.Removed() != 0 {
		t.Fatalf("Put(older) = inserted %v removed %d, want false 0", got.Inserted(), got.Removed())
	}
	newer := testSignedEntry(namespace, author, "k", testRecord("two", 1, 2))
	if got := store.Put(newer); !got.Inserted() || got.Removed() != 1 {
		t.Fatalf("Put(newer) = inserted %v removed %d, want true 1", got.Inserted(), got.Removed())
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
	got, ok := store.GetExact(namespace.ID(), author.ID(), []byte("k"), false)
	if !ok {
		t.Fatal("GetExact missing inserted entry")
	}
	if !got.Equal(newer) {
		t.Fatal("GetExact returned stale entry")
	}
}

func TestMemoryStorePrefixDeletion(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	other := NewAuthor(repeat32(0xc3))
	store := NewMemoryStore()

	store.Put(testSignedEntry(namespace, author, "dir/a", testRecord("a", 1, 1)))
	store.Put(testSignedEntry(namespace, author, "dir/b", testRecord("b", 1, 1)))
	store.Put(testSignedEntry(namespace, author, "other", testRecord("other", 1, 1)))
	store.Put(testSignedEntry(namespace, other, "dir/a", testRecord("other-author", 1, 1)))

	tombstone := testSignedEntry(namespace, author, "dir", EmptyRecord(2))
	if got := store.Put(tombstone); !got.Inserted() || got.Removed() != 2 {
		t.Fatalf("Put(tombstone) = inserted %v removed %d, want true 2", got.Inserted(), got.Removed())
	}
	if store.Len() != 3 {
		t.Fatalf("Len = %d, want 3", store.Len())
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("dir"), false); ok {
		t.Fatal("GetExact returned tombstone without includeEmpty")
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("dir"), true); !ok {
		t.Fatal("GetExact missing tombstone with includeEmpty")
	}
	if _, ok := store.GetExact(namespace.ID(), author.ID(), []byte("dir/a"), true); ok {
		t.Fatal("GetExact returned removed child")
	}
	if _, ok := store.GetExact(namespace.ID(), other.ID(), []byte("dir/a"), false); !ok {
		t.Fatal("prefix delete removed another author's entry")
	}
}

func TestMemoryStoreParentBlocksChild(t *testing.T) {
	namespace := NewNamespaceSecret(repeat32(0xb2))
	author := NewAuthor(repeat32(0xa1))
	store := NewMemoryStore()

	parent := testSignedEntry(namespace, author, "dir", EmptyRecord(2))
	if got := store.Put(parent); !got.Inserted() {
		t.Fatal("Put(parent) was not inserted")
	}
	child := testSignedEntry(namespace, author, "dir/a", testRecord("a", 1, 1))
	if got := store.Put(child); got.Inserted() {
		t.Fatal("older child inserted below newer parent")
	}
	if store.Len() != 1 {
		t.Fatalf("Len = %d, want 1", store.Len())
	}
}

func testSignedEntry(namespace NamespaceSecret, author Author, key string, record Record) SignedEntry {
	id := NewRecordIdentifier(namespace.ID(), author.ID(), []byte(key))
	return NewSignedEntry(NewEntry(id, record), namespace, author)
}

func testRecord(seed string, length, timestamp uint64) Record {
	return NewRecord(blobs.NewHash([]byte(seed)), length, timestamp)
}
